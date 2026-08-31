//! Transport state for QUIC paths, connection IDs, and flow control.
//!
//! This module deliberately performs no I/O and has no dependency on timers or
//! randomness.  The caller supplies timestamps and PATH_CHALLENGE bytes and
//! executes the returned actions.

use std::cmp;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::types::{Role, StreamId, VARINT_MAX};

pub const MAX_CONNECTION_ID_LEN: usize = 20;
pub const STATELESS_RESET_TOKEN_LEN: usize = 16;
pub const MIN_ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;
pub const MIN_INITIAL_DATAGRAM_SIZE: u16 = 1200;
pub const MAX_PATHS: usize = 4;
const PMTU_PROBE_SIZES: [u16; 4] = [1280, 1350, 1452, 1472];

/// An address in a representation that round-trips both IPv4 and IPv6
/// `SocketAddr` values, including IPv6 scope and flow information.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NetworkAddress(pub SocketAddr);

impl NetworkAddress {
    pub const fn new(address: SocketAddr) -> Self {
        Self(address)
    }

    pub fn ip(self) -> IpAddr {
        self.0.ip()
    }

    pub fn port(self) -> u16 {
        self.0.port()
    }
}

impl From<SocketAddr> for NetworkAddress {
    fn from(value: SocketAddr) -> Self {
        Self(value)
    }
}

impl From<NetworkAddress> for SocketAddr {
    fn from(value: NetworkAddress) -> Self {
        value.0
    }
}

impl fmt::Display for NetworkAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PathId(u64);

impl PathId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathValidationState {
    Unvalidated,
    Challenging {
        challenge: [u8; 8],
        sent_at: Duration,
        attempts: u8,
    },
    Validated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PmtuProbeStatus {
    Idle,
    InFlight {
        packet_number: u64,
        size: u16,
        sent_at: Duration,
    },
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PmtuState {
    current: u16,
    upper_bound: u16,
    next_probe: u16,
    status: PmtuProbeStatus,
}

impl PmtuState {
    pub fn new(current: u16, upper_bound: u16) -> Result<Self, PathError> {
        if current < MIN_INITIAL_DATAGRAM_SIZE || upper_bound < current {
            return Err(PathError::InvalidPmtuBounds {
                current,
                upper_bound,
            });
        }
        let next_probe = next_pmtu_probe(current, upper_bound).unwrap_or(current);
        Ok(Self {
            current,
            upper_bound,
            next_probe,
            status: if next_probe > current {
                PmtuProbeStatus::Idle
            } else {
                PmtuProbeStatus::Complete
            },
        })
    }

    pub const fn current(&self) -> u16 {
        self.current
    }

    #[cfg(test)]
    pub const fn upper_bound(&self) -> u16 {
        self.upper_bound
    }

    pub const fn status(&self) -> PmtuProbeStatus {
        self.status
    }

    pub fn next_probe_size(&self) -> Option<u16> {
        match self.status {
            PmtuProbeStatus::Idle => Some(self.next_probe),
            PmtuProbeStatus::InFlight { .. } | PmtuProbeStatus::Complete => None,
        }
    }

    pub fn probe_sent(
        &mut self,
        packet_number: u64,
        size: u16,
        now: Duration,
    ) -> Result<(), PathError> {
        if self.status != PmtuProbeStatus::Idle || size != self.next_probe {
            return Err(PathError::InvalidPmtuProbe);
        }
        self.status = PmtuProbeStatus::InFlight {
            packet_number,
            size,
            sent_at: now,
        };
        Ok(())
    }

    pub fn probe_acked(&mut self, packet_number: u64) -> Result<u16, PathError> {
        let size = match self.status {
            PmtuProbeStatus::InFlight {
                packet_number: expected,
                size,
                ..
            } if expected == packet_number => size,
            _ => return Err(PathError::UnknownPmtuProbe(packet_number)),
        };
        self.current = size;
        self.advance();
        Ok(size)
    }

    pub fn probe_lost(&mut self, packet_number: u64) -> Result<u16, PathError> {
        let size = match self.status {
            PmtuProbeStatus::InFlight {
                packet_number: expected,
                size,
                ..
            } if expected == packet_number => size,
            _ => return Err(PathError::UnknownPmtuProbe(packet_number)),
        };
        self.upper_bound = size.saturating_sub(1).max(self.current);
        self.advance();
        Ok(size)
    }

    pub fn cap_upper_bound(&mut self, upper_bound: u16) -> Result<(), PathError> {
        if upper_bound < MIN_INITIAL_DATAGRAM_SIZE {
            return Err(PathError::InvalidPmtuBounds {
                current: self.current,
                upper_bound,
            });
        }
        self.current = self.current.min(upper_bound);
        self.upper_bound = self.upper_bound.min(upper_bound);
        self.next_probe = next_pmtu_probe(self.current, self.upper_bound).unwrap_or(self.current);
        self.status = if self.next_probe > self.current {
            PmtuProbeStatus::Idle
        } else {
            PmtuProbeStatus::Complete
        };
        Ok(())
    }

    pub fn fall_back_to(&mut self, current: u16) -> Result<(), PathError> {
        if current < MIN_INITIAL_DATAGRAM_SIZE || current > self.current {
            return Err(PathError::InvalidPmtuBounds {
                current,
                upper_bound: self.upper_bound,
            });
        }
        self.current = current;
        self.advance();
        Ok(())
    }

    fn advance(&mut self) {
        if let Some(next_probe) = next_pmtu_probe(self.current, self.upper_bound) {
            self.next_probe = next_probe;
            self.status = PmtuProbeStatus::Idle;
        } else {
            self.status = PmtuProbeStatus::Complete;
        }
    }
}

fn next_pmtu_probe(current: u16, upper_bound: u16) -> Option<u16> {
    PMTU_PROBE_SIZES
        .into_iter()
        .find(|size| *size > current && *size <= upper_bound)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathState {
    pub id: PathId,
    pub local: NetworkAddress,
    pub remote: NetworkAddress,
    pub validation: PathValidationState,
    pub pmtu: PmtuState,
    bytes_sent: u64,
    bytes_received: u64,
    anti_amplification_limited: bool,
}

impl PathState {
    pub fn new(
        id: PathId,
        local: NetworkAddress,
        remote: NetworkAddress,
        role: Role,
        peer_address_validated: bool,
        pmtu: PmtuState,
    ) -> Self {
        let validated = role == Role::Client || peer_address_validated;
        Self {
            id,
            local,
            remote,
            validation: if validated {
                PathValidationState::Validated
            } else {
                PathValidationState::Unvalidated
            },
            pmtu,
            bytes_sent: 0,
            bytes_received: 0,
            anti_amplification_limited: role == Role::Server && !validated,
        }
    }

    pub const fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    pub const fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    pub fn receive(&mut self, bytes: usize) {
        self.bytes_received = self.bytes_received.saturating_add(usize_to_u64(bytes));
    }

    pub fn validate(&mut self) {
        self.validation = PathValidationState::Validated;
        self.anti_amplification_limited = false;
    }

    pub fn send_allowance(&self) -> u64 {
        if !self.anti_amplification_limited || self.validation == PathValidationState::Validated {
            u64::MAX
        } else {
            self.bytes_received
                .saturating_mul(3)
                .saturating_sub(self.bytes_sent)
        }
    }

    pub fn record_sent(&mut self, bytes: usize) -> Result<(), PathError> {
        let bytes = usize_to_u64(bytes);
        if bytes > self.send_allowance() {
            return Err(PathError::AntiAmplificationLimit {
                attempted: bytes,
                allowance: self.send_allowance(),
            });
        }
        self.bytes_sent = self.bytes_sent.saturating_add(bytes);
        Ok(())
    }

    pub fn start_validation(
        &mut self,
        challenge: [u8; 8],
        now: Duration,
    ) -> Result<PathAction, PathError> {
        let attempts = match self.validation {
            PathValidationState::Validated => return Err(PathError::PathAlreadyValidated),
            PathValidationState::Unvalidated => 1,
            PathValidationState::Challenging { attempts, .. } => attempts
                .checked_add(1)
                .ok_or(PathError::TooManyValidationAttempts)?,
        };
        self.validation = PathValidationState::Challenging {
            challenge,
            sent_at: now,
            attempts,
        };
        Ok(PathAction::SendChallenge {
            path: self.id,
            data: challenge,
        })
    }

    pub fn receive_response(&mut self, response: [u8; 8]) -> Result<PathAction, PathError> {
        match self.validation {
            PathValidationState::Challenging { challenge, .. } if challenge == response => {
                self.validation = PathValidationState::Validated;
                self.anti_amplification_limited = false;
                Ok(PathAction::PathValidated(self.id))
            }
            PathValidationState::Challenging { .. } => Err(PathError::ChallengeMismatch),
            _ => Err(PathError::NoChallengeOutstanding),
        }
    }
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathAction {
    SendChallenge { path: PathId, data: [u8; 8] },
    PathValidated(PathId),
    ActivePathChanged { previous: PathId, current: PathId },
    PeerMigrationDetected { previous: PathId, candidate: PathId },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathError {
    UnknownPath(PathId),
    PathIdExhausted,
    PathLimitExceeded,
    CannotActivateUnvalidatedPath(PathId),
    AntiAmplificationLimit { attempted: u64, allowance: u64 },
    PathAlreadyValidated,
    TooManyValidationAttempts,
    ChallengeMismatch,
    NoChallengeOutstanding,
    InvalidPmtuBounds { current: u16, upper_bound: u16 },
    InvalidPmtuProbe,
    UnknownPmtuProbe(u64),
}

#[derive(Clone, Debug)]
pub struct PathManager {
    role: Role,
    paths: BTreeMap<PathId, PathState>,
    addresses: BTreeMap<(NetworkAddress, NetworkAddress), PathId>,
    active: PathId,
    next_id: u64,
    default_pmtu_current: u16,
    default_pmtu_upper_bound: u16,
}

impl PathManager {
    pub fn new(
        role: Role,
        local: NetworkAddress,
        remote: NetworkAddress,
        peer_address_validated: bool,
        pmtu_current: u16,
        pmtu_upper_bound: u16,
    ) -> Result<Self, PathError> {
        let id = PathId::new(0);
        let pmtu = PmtuState::new(pmtu_current, pmtu_upper_bound)?;
        let path = PathState::new(id, local, remote, role, peer_address_validated, pmtu);
        let mut paths = BTreeMap::new();
        paths.insert(id, path);
        let mut addresses = BTreeMap::new();
        addresses.insert((local, remote), id);
        Ok(Self {
            role,
            paths,
            addresses,
            active: id,
            next_id: 1,
            default_pmtu_current: pmtu_current,
            default_pmtu_upper_bound: pmtu_upper_bound,
        })
    }

    pub const fn active_path_id(&self) -> PathId {
        self.active
    }

    pub fn active_path(&self) -> &PathState {
        // The active path is inserted at construction and is never removed.
        &self.paths[&self.active]
    }

    pub fn path(&self, id: PathId) -> Option<&PathState> {
        self.paths.get(&id)
    }

    pub fn path_mut(&mut self, id: PathId) -> Option<&mut PathState> {
        self.paths.get_mut(&id)
    }

    pub fn find(&self, local: NetworkAddress, remote: NetworkAddress) -> Option<PathId> {
        self.addresses.get(&(local, remote)).copied()
    }

    pub fn observe_remote(
        &mut self,
        local: NetworkAddress,
        remote: NetworkAddress,
    ) -> Result<(PathId, Option<PathAction>), PathError> {
        if let Some(id) = self.find(local, remote) {
            return Ok((id, None));
        }
        if self.paths.len() >= MAX_PATHS {
            return Err(PathError::PathLimitExceeded);
        }
        let id = PathId::new(self.next_id);
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(PathError::PathIdExhausted)?;
        let pmtu = PmtuState::new(self.default_pmtu_current, self.default_pmtu_upper_bound)?;
        let mut path = PathState::new(id, local, remote, self.role, false, pmtu);
        // Every new tuple needs path validation; clients are exempt only from
        // anti-amplification, not from migration validation.
        path.validation = PathValidationState::Unvalidated;
        self.paths.insert(id, path);
        self.addresses.insert((local, remote), id);
        Ok((
            id,
            Some(PathAction::PeerMigrationDetected {
                previous: self.active,
                candidate: id,
            }),
        ))
    }

    pub fn cap_pmtu(&mut self, upper_bound: u16) -> Result<(), PathError> {
        self.default_pmtu_upper_bound = self.default_pmtu_upper_bound.min(upper_bound);
        for path in self.paths.values_mut() {
            path.pmtu.cap_upper_bound(upper_bound)?;
        }
        Ok(())
    }

    pub fn fall_back_active_pmtu(&mut self, current: u16) -> Result<(), PathError> {
        self.paths
            .get_mut(&self.active)
            .ok_or(PathError::UnknownPath(self.active))?
            .pmtu
            .fall_back_to(current)
    }

    pub fn activate(&mut self, id: PathId) -> Result<Option<PathAction>, PathError> {
        let path = self.paths.get(&id).ok_or(PathError::UnknownPath(id))?;
        if path.validation != PathValidationState::Validated {
            return Err(PathError::CannotActivateUnvalidatedPath(id));
        }
        if id == self.active {
            return Ok(None);
        }
        let previous = self.active;
        self.active = id;
        Ok(Some(PathAction::ActivePathChanged {
            previous,
            current: id,
        }))
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionId(Vec<u8>);

impl ConnectionId {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, CidError> {
        let bytes = bytes.into();
        if bytes.len() > MAX_CONNECTION_ID_LEN {
            return Err(CidError::ConnectionIdTooLong(bytes.len()));
        }
        Ok(Self(bytes))
    }

    pub fn for_new_connection_id(bytes: impl Into<Vec<u8>>) -> Result<Self, CidError> {
        let cid = Self::new(bytes)?;
        if cid.is_empty() {
            return Err(CidError::EmptyConnectionId);
        }
        Ok(cid)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionIdEntry {
    pub sequence: u64,
    pub connection_id: ConnectionId,
    pub reset_token: [u8; STATELESS_RESET_TOKEN_LEN],
    pub retired: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CidAction {
    RetirePeer(u64),
    AdvertiseLocal(ConnectionIdEntry),
    LocalRetired(u64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CidError {
    ConnectionIdTooLong(usize),
    EmptyConnectionId,
    InvalidActiveConnectionIdLimit(u64),
    SequenceOutOfRange(u64),
    RetirePriorToExceedsSequence {
        retire_prior_to: u64,
        sequence: u64,
    },
    ConflictingSequence(u64),
    DuplicateConnectionId,
    DuplicateResetToken,
    ActiveConnectionIdLimitExceeded {
        limit: u64,
    },
    UnknownSequence(u64),
    AlreadyRetired(u64),
    #[cfg(test)]
    ConnectionIdInUse(u64),
    SequenceExhausted,
}

#[derive(Clone, Debug)]
pub struct PeerCidStore {
    active_limit: u64,
    retire_prior_to: u64,
    entries: BTreeMap<u64, ConnectionIdEntry>,
    assigned: BTreeMap<PathId, u64>,
    initial_reset_token: Option<[u8; STATELESS_RESET_TOKEN_LEN]>,
}

impl PeerCidStore {
    pub fn new(active_limit: u64) -> Result<Self, CidError> {
        validate_active_limit(active_limit)?;
        Ok(Self {
            active_limit,
            retire_prior_to: 0,
            entries: BTreeMap::new(),
            assigned: BTreeMap::new(),
            initial_reset_token: None,
        })
    }

    #[cfg(test)]
    pub const fn retire_prior_to(&self) -> u64 {
        self.retire_prior_to
    }

    #[cfg(test)]
    pub fn get(&self, sequence: u64) -> Option<&ConnectionIdEntry> {
        self.entries.get(&sequence)
    }

    pub fn replace_initial(&mut self, connection_id: ConnectionId) -> Result<(), CidError> {
        if connection_id.is_empty() {
            return Err(CidError::EmptyConnectionId);
        }
        if self
            .entries
            .iter()
            .any(|(sequence, entry)| *sequence != 0 && entry.connection_id == connection_id)
        {
            return Err(CidError::DuplicateConnectionId);
        }
        let entry = self
            .entries
            .get_mut(&0)
            .ok_or(CidError::UnknownSequence(0))?;
        entry.connection_id = connection_id;
        Ok(())
    }

    pub fn install_initial_reset_token(
        &mut self,
        token: [u8; STATELESS_RESET_TOKEN_LEN],
    ) -> Result<(), CidError> {
        if self
            .entries
            .iter()
            .any(|(&sequence, entry)| sequence != 0 && entry.reset_token == token)
        {
            return Err(CidError::DuplicateResetToken);
        }
        let entry = self
            .entries
            .get_mut(&0)
            .ok_or(CidError::UnknownSequence(0))?;
        entry.reset_token = token;
        self.initial_reset_token = Some(token);
        Ok(())
    }

    pub fn insert(
        &mut self,
        sequence: u64,
        retire_prior_to: u64,
        connection_id: ConnectionId,
        reset_token: [u8; STATELESS_RESET_TOKEN_LEN],
    ) -> Result<Vec<CidAction>, CidError> {
        validate_sequence(sequence)?;
        validate_sequence(retire_prior_to)?;
        if connection_id.is_empty() {
            return Err(CidError::EmptyConnectionId);
        }
        if retire_prior_to > sequence {
            return Err(CidError::RetirePriorToExceedsSequence {
                retire_prior_to,
                sequence,
            });
        }
        let already_present = if let Some(existing) = self.entries.get(&sequence) {
            if existing.connection_id != connection_id || existing.reset_token != reset_token {
                return Err(CidError::ConflictingSequence(sequence));
            }
            true
        } else {
            if self
                .entries
                .values()
                .any(|entry| entry.connection_id == connection_id)
            {
                return Err(CidError::DuplicateConnectionId);
            }
            if self.entries.iter().any(|(&entry_sequence, entry)| {
                entry.reset_token == reset_token
                    && (entry_sequence != 0 || self.initial_reset_token.is_some())
            }) {
                return Err(CidError::DuplicateResetToken);
            }
            false
        };

        let effective_retire = cmp::max(self.retire_prior_to, retire_prior_to);
        let retained = self
            .entries
            .values()
            .filter(|entry| !entry.retired && entry.sequence >= effective_retire)
            .count() as u64;
        let new_is_active = !already_present && sequence >= effective_retire;
        if retained.saturating_add(u64::from(new_is_active)) > self.active_limit {
            return Err(CidError::ActiveConnectionIdLimitExceeded {
                limit: self.active_limit,
            });
        }

        if !already_present {
            self.entries.insert(
                sequence,
                ConnectionIdEntry {
                    sequence,
                    connection_id,
                    reset_token,
                    retired: sequence < effective_retire,
                },
            );
        }
        self.retire_prior_to = effective_retire;

        let mut actions = Vec::new();
        for entry in self.entries.values_mut() {
            if entry.sequence < effective_retire && !entry.retired {
                entry.retired = true;
                actions.push(CidAction::RetirePeer(entry.sequence));
            }
        }
        let retired: BTreeSet<u64> = actions
            .iter()
            .filter_map(|action| match action {
                CidAction::RetirePeer(sequence) => Some(*sequence),
                _ => None,
            })
            .collect();
        self.assigned
            .retain(|_, sequence| !retired.contains(sequence));
        Ok(actions)
    }

    pub fn assign_to_path(&mut self, path: PathId) -> Result<&ConnectionIdEntry, CidError> {
        if let Some(sequence) = self.assigned.get(&path) {
            return self
                .entries
                .get(sequence)
                .ok_or(CidError::UnknownSequence(*sequence));
        }
        let in_use: BTreeSet<u64> = self.assigned.values().copied().collect();
        let sequence = self
            .entries
            .iter()
            .find(|(sequence, entry)| !entry.retired && !in_use.contains(sequence))
            .map(|(sequence, _)| *sequence)
            .ok_or(CidError::ActiveConnectionIdLimitExceeded {
                limit: self.active_limit,
            })?;
        self.assigned.insert(path, sequence);
        self.entries
            .get(&sequence)
            .ok_or(CidError::UnknownSequence(sequence))
    }

    pub fn assigned_to_path(&self, path: PathId) -> Option<&ConnectionIdEntry> {
        self.assigned
            .get(&path)
            .and_then(|sequence| self.entries.get(sequence))
    }

    pub fn rotate_path(&mut self, path: PathId) -> Result<(u64, &ConnectionIdEntry), CidError> {
        let previous = self
            .assigned
            .get(&path)
            .copied()
            .ok_or(CidError::UnknownSequence(0))?;
        let in_use: BTreeSet<u64> = self
            .assigned
            .iter()
            .filter_map(|(assigned_path, sequence)| (*assigned_path != path).then_some(*sequence))
            .collect();
        let next = self
            .entries
            .iter()
            .find(|(sequence, entry)| {
                **sequence != previous && !entry.retired && !in_use.contains(sequence)
            })
            .map(|(sequence, _)| *sequence)
            .ok_or(CidError::ActiveConnectionIdLimitExceeded {
                limit: self.active_limit,
            })?;
        self.entries
            .get_mut(&previous)
            .ok_or(CidError::UnknownSequence(previous))?
            .retired = true;
        self.assigned.insert(path, next);
        let current = self
            .entries
            .get(&next)
            .ok_or(CidError::UnknownSequence(next))?;
        Ok((previous, current))
    }

    pub fn move_assignment(
        &mut self,
        from: PathId,
        to: PathId,
    ) -> Result<&ConnectionIdEntry, CidError> {
        let sequence = if let Some(sequence) = self.assigned.get(&to).copied() {
            sequence
        } else {
            let sequence = self
                .assigned
                .remove(&from)
                .ok_or(CidError::UnknownSequence(0))?;
            self.assigned.insert(to, sequence);
            sequence
        };
        Ok(&self.entries[&sequence])
    }

    #[cfg(test)]
    pub fn release_path(&mut self, path: PathId) -> Option<u64> {
        self.assigned.remove(&path)
    }

    #[cfg(test)]
    pub fn retire(&mut self, sequence: u64) -> Result<CidAction, CidError> {
        if self.assigned.values().any(|assigned| *assigned == sequence) {
            return Err(CidError::ConnectionIdInUse(sequence));
        }
        let entry = self
            .entries
            .get_mut(&sequence)
            .ok_or(CidError::UnknownSequence(sequence))?;
        if entry.retired {
            return Err(CidError::AlreadyRetired(sequence));
        }
        entry.retired = true;
        Ok(CidAction::RetirePeer(sequence))
    }

    pub fn matches_reset_token(&self, token: &[u8]) -> bool {
        if token.len() != STATELESS_RESET_TOKEN_LEN {
            return false;
        }
        let mut matched = false;
        for entry in self.entries.values().filter(|entry| !entry.retired) {
            matched |= if entry.sequence == 0 {
                self.initial_reset_token
                    .as_ref()
                    .is_some_and(|initial| constant_time_eq(initial, token))
            } else {
                constant_time_eq(&entry.reset_token, token)
            };
        }
        matched
    }
}

#[derive(Clone, Debug)]
pub struct LocalCidStore {
    peer_active_limit: u64,
    next_sequence: u64,
    entries: BTreeMap<u64, ConnectionIdEntry>,
    assigned: BTreeMap<PathId, u64>,
}

impl LocalCidStore {
    pub fn new(peer_active_limit: u64) -> Result<Self, CidError> {
        validate_active_limit(peer_active_limit)?;
        Ok(Self {
            peer_active_limit,
            next_sequence: 0,
            entries: BTreeMap::new(),
            assigned: BTreeMap::new(),
        })
    }

    pub fn issue(
        &mut self,
        connection_id: ConnectionId,
        reset_token: [u8; STATELESS_RESET_TOKEN_LEN],
    ) -> Result<CidAction, CidError> {
        if connection_id.is_empty() {
            return Err(CidError::EmptyConnectionId);
        }
        if self
            .entries
            .values()
            .any(|entry| entry.connection_id == connection_id)
        {
            return Err(CidError::DuplicateConnectionId);
        }
        if self
            .entries
            .values()
            .any(|entry| entry.reset_token == reset_token)
        {
            return Err(CidError::DuplicateResetToken);
        }
        if self.entries.values().filter(|entry| !entry.retired).count() as u64
            >= self.peer_active_limit
        {
            return Err(CidError::ActiveConnectionIdLimitExceeded {
                limit: self.peer_active_limit,
            });
        }
        validate_sequence(self.next_sequence)?;
        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(CidError::SequenceExhausted)?;
        let entry = ConnectionIdEntry {
            sequence,
            connection_id,
            reset_token,
            retired: false,
        };
        self.entries.insert(sequence, entry.clone());
        Ok(CidAction::AdvertiseLocal(entry))
    }

    pub fn set_peer_active_limit(&mut self, limit: u64) -> Result<(), CidError> {
        validate_active_limit(limit)?;
        self.peer_active_limit = limit;
        Ok(())
    }

    pub fn active_count(&self) -> u64 {
        self.entries.values().filter(|entry| !entry.retired).count() as u64
    }

    pub fn peer_active_limit(&self) -> u64 {
        self.peer_active_limit
    }

    pub fn sequence_for_cid(&self, connection_id: &[u8]) -> Option<u64> {
        self.entries
            .iter()
            .find(|(_, entry)| !entry.retired && entry.connection_id.as_bytes() == connection_id)
            .map(|(sequence, _)| *sequence)
    }

    pub fn assign_to_path(&mut self, path: PathId, sequence: u64) -> Result<(), CidError> {
        let entry = self
            .entries
            .get(&sequence)
            .ok_or(CidError::UnknownSequence(sequence))?;
        if entry.retired {
            return Err(CidError::AlreadyRetired(sequence));
        }
        self.assigned.insert(path, sequence);
        Ok(())
    }

    pub fn retire_from_peer(&mut self, sequence: u64) -> Result<CidAction, CidError> {
        let entry = self
            .entries
            .get_mut(&sequence)
            .ok_or(CidError::UnknownSequence(sequence))?;
        if entry.retired {
            return Err(CidError::AlreadyRetired(sequence));
        }
        entry.retired = true;
        self.assigned.retain(|_, assigned| *assigned != sequence);
        Ok(CidAction::LocalRetired(sequence))
    }

    pub fn get(&self, sequence: u64) -> Option<&ConnectionIdEntry> {
        self.entries.get(&sequence)
    }
}

fn validate_active_limit(limit: u64) -> Result<(), CidError> {
    if !(MIN_ACTIVE_CONNECTION_ID_LIMIT..=VARINT_MAX).contains(&limit) {
        Err(CidError::InvalidActiveConnectionIdLimit(limit))
    } else {
        Ok(())
    }
}

fn validate_sequence(sequence: u64) -> Result<(), CidError> {
    if sequence > VARINT_MAX {
        Err(CidError::SequenceOutOfRange(sequence))
    } else {
        Ok(())
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (&left, &right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowAction {
    SendMaxData(u64),
    SendMaxStreamData { stream: StreamId, maximum: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowError {
    ValueOutOfRange(u64),
    ConnectionSendLimit {
        attempted: u64,
        maximum: u64,
    },
    ConnectionReceiveLimit {
        attempted: u64,
        maximum: u64,
    },
    StreamSendLimit {
        stream: StreamId,
        attempted: u64,
        maximum: u64,
    },
    StreamReceiveLimit {
        stream: StreamId,
        attempted: u64,
        maximum: u64,
    },
    FinalSizeChanged {
        stream: StreamId,
    },
    FinalSizeSmallerThanReceived {
        stream: StreamId,
    },
    StreamNotFound(StreamId),
    ReservationIdExhausted,
    UnknownSendReservation(u64),
    UnknownReceiveReservation(u64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowLimit {
    maximum: u64,
    used: u64,
    consumed: u64,
    window: u64,
    pending_update: Option<u64>,
}

impl FlowLimit {
    pub fn new(maximum: u64, window: u64) -> Result<Self, FlowError> {
        validate_flow_value(maximum)?;
        validate_flow_value(window)?;
        Ok(Self {
            maximum,
            used: 0,
            consumed: 0,
            window,
            pending_update: None,
        })
    }

    #[cfg(test)]
    pub const fn used(&self) -> u64 {
        self.used
    }

    fn consume(&mut self, amount: u64) -> Result<Option<u64>, FlowError> {
        validate_flow_value(amount)?;
        self.consumed = self.consumed.saturating_add(amount).min(self.used);
        let remaining = self.maximum.saturating_sub(self.used);
        let threshold = self.window / 2;
        if remaining <= threshold {
            let desired = self.consumed.saturating_add(self.window).min(VARINT_MAX);
            if desired > self.maximum {
                self.maximum = desired;
                self.pending_update = Some(desired);
                return Ok(Some(desired));
            }
        }
        Ok(None)
    }

    fn take_update(&mut self) -> Option<u64> {
        self.pending_update.take()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamFlowState {
    pub id: StreamId,
    send_maximum: u64,
    sent: u64,
    receive: FlowLimit,
    final_size: Option<u64>,
}

impl StreamFlowState {
    pub fn new(
        id: StreamId,
        send_maximum: u64,
        receive_maximum: u64,
        receive_window: u64,
    ) -> Result<Self, FlowError> {
        validate_flow_value(id.into_inner())?;
        validate_flow_value(send_maximum)?;
        Ok(Self {
            id,
            send_maximum,
            sent: 0,
            receive: FlowLimit::new(receive_maximum, receive_window)?,
            final_size: None,
        })
    }

    pub const fn send_maximum(&self) -> u64 {
        self.send_maximum
    }

    #[cfg(test)]
    pub const fn sent(&self) -> u64 {
        self.sent
    }

    #[cfg(test)]
    pub const fn received(&self) -> u64 {
        self.receive.used
    }

    #[cfg(test)]
    pub const fn final_size(&self) -> Option<u64> {
        self.final_size
    }

    pub fn increase_send_maximum(&mut self, maximum: u64) -> Result<bool, FlowError> {
        validate_flow_value(maximum)?;
        if maximum > self.send_maximum {
            self.send_maximum = maximum;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn replace_send_maximum(&mut self, maximum: u64) -> Result<(), FlowError> {
        validate_flow_value(maximum)?;
        self.send_maximum = maximum;
        Ok(())
    }

    fn receive_to(&mut self, end_offset: u64, final_size: bool) -> Result<u64, FlowError> {
        validate_flow_value(end_offset)?;
        if end_offset > self.receive.maximum {
            return Err(FlowError::StreamReceiveLimit {
                stream: self.id,
                attempted: end_offset,
                maximum: self.receive.maximum,
            });
        }
        if let Some(known) = self.final_size {
            if final_size && known != end_offset || end_offset > known {
                return Err(FlowError::FinalSizeChanged { stream: self.id });
            }
        }
        if final_size {
            if end_offset < self.receive.used {
                return Err(FlowError::FinalSizeSmallerThanReceived { stream: self.id });
            }
            self.final_size = Some(end_offset);
        }
        let increment = end_offset.saturating_sub(self.receive.used);
        self.receive.used = cmp::max(self.receive.used, end_offset);
        Ok(increment)
    }
}

#[derive(Debug, Eq, PartialEq)]
#[must_use = "a send reservation must be committed or canceled"]
pub struct SendReservation {
    id: u64,
    stream: StreamId,
    end_offset: u64,
    new_bytes: u64,
}

impl SendReservation {
    #[cfg(test)]
    pub const fn new_bytes(&self) -> u64 {
        self.new_bytes
    }
}

#[derive(Debug, Eq, PartialEq)]
#[must_use = "a receive reservation must be committed or canceled"]
pub struct ReceiveReservation {
    id: u64,
    stream: StreamId,
    end_offset: u64,
    final_size: bool,
    new_bytes: u64,
}

impl ReceiveReservation {
    #[cfg(test)]
    pub const fn new_bytes(&self) -> u64 {
        self.new_bytes
    }
}

#[derive(Clone, Debug)]
struct PendingReceive {
    stream: StreamId,
    end_offset: u64,
    final_size: bool,
}

#[derive(Clone, Debug)]
pub struct FlowController {
    connection_send_maximum: u64,
    connection_sent: u64,
    provisional_connection_sent: u64,
    connection_receive: FlowLimit,
    provisional_connection_received: u64,
    streams: BTreeMap<StreamId, StreamFlowState>,
    next_reservation_id: u64,
    pending_sends: BTreeMap<u64, (StreamId, u64)>,
    pending_receives: BTreeMap<u64, PendingReceive>,
}

impl FlowController {
    pub fn new(
        connection_send_maximum: u64,
        connection_receive_maximum: u64,
        connection_receive_window: u64,
    ) -> Result<Self, FlowError> {
        validate_flow_value(connection_send_maximum)?;
        Ok(Self {
            connection_send_maximum,
            connection_sent: 0,
            provisional_connection_sent: 0,
            connection_receive: FlowLimit::new(
                connection_receive_maximum,
                connection_receive_window,
            )?,
            provisional_connection_received: 0,
            streams: BTreeMap::new(),
            next_reservation_id: 0,
            pending_sends: BTreeMap::new(),
            pending_receives: BTreeMap::new(),
        })
    }

    pub fn insert_stream(&mut self, stream: StreamFlowState) -> Result<(), FlowError> {
        validate_flow_value(stream.id.into_inner())?;
        self.streams.insert(stream.id, stream);
        Ok(())
    }

    pub fn stream(&self, id: StreamId) -> Option<&StreamFlowState> {
        self.streams.get(&id)
    }

    pub fn stream_mut(&mut self, id: StreamId) -> Option<&mut StreamFlowState> {
        self.streams.get_mut(&id)
    }

    pub fn remove_stream(&mut self, id: StreamId) {
        self.streams.remove(&id);
    }

    #[cfg(test)]
    pub const fn connection_sent(&self) -> u64 {
        self.connection_sent
    }

    #[cfg(test)]
    pub const fn connection_received(&self) -> u64 {
        self.connection_receive.used
    }

    pub fn increase_connection_send_maximum(&mut self, maximum: u64) -> Result<bool, FlowError> {
        validate_flow_value(maximum)?;
        if maximum > self.connection_send_maximum {
            self.connection_send_maximum = maximum;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn replace_connection_send_maximum(&mut self, maximum: u64) -> Result<(), FlowError> {
        validate_flow_value(maximum)?;
        self.connection_send_maximum = maximum;
        Ok(())
    }

    /// Checks an exclusive stream end offset without reserving or consuming credit.
    pub fn check_send(&self, stream: StreamId, end_offset: u64) -> Result<(), FlowError> {
        validate_flow_value(end_offset)?;
        let state = self
            .streams
            .get(&stream)
            .ok_or(FlowError::StreamNotFound(stream))?;
        if end_offset > state.send_maximum {
            return Err(FlowError::StreamSendLimit {
                stream,
                attempted: end_offset,
                maximum: state.send_maximum,
            });
        }

        let previous = self.provisional_send_offset(stream);
        let increment = end_offset.saturating_sub(previous);
        let attempted = self.provisional_connection_sent().saturating_add(increment);
        if attempted > self.connection_send_maximum || attempted > VARINT_MAX {
            return Err(FlowError::ConnectionSendLimit {
                attempted,
                maximum: self.connection_send_maximum,
            });
        }
        Ok(())
    }

    /// Reserves credit through an exclusive stream end offset.
    pub fn prepare_send(
        &mut self,
        stream: StreamId,
        end_offset: u64,
    ) -> Result<SendReservation, FlowError> {
        self.check_send(stream, end_offset)?;
        let new_bytes = end_offset.saturating_sub(self.provisional_send_offset(stream));
        let id = self.allocate_reservation_id()?;
        self.pending_sends.insert(id, (stream, end_offset));
        self.provisional_connection_sent =
            self.provisional_connection_sent.saturating_add(new_bytes);
        Ok(SendReservation {
            id,
            stream,
            end_offset,
            new_bytes,
        })
    }

    pub fn commit_send(&mut self, reservation: SendReservation) -> Result<(), FlowError> {
        let (stream, end_offset) = self
            .pending_sends
            .remove(&reservation.id)
            .ok_or(FlowError::UnknownSendReservation(reservation.id))?;
        let state = self
            .streams
            .get_mut(&stream)
            .ok_or(FlowError::StreamNotFound(stream))?;
        let increment = end_offset.saturating_sub(state.sent);
        state.sent = cmp::max(state.sent, end_offset);
        self.connection_sent = self.connection_sent.saturating_add(increment);
        Ok(())
    }

    #[cfg(test)]
    pub fn cancel_send(&mut self, reservation: SendReservation) -> Result<(), FlowError> {
        let before = self.provisional_send_offset(reservation.stream);
        self.pending_sends
            .remove(&reservation.id)
            .ok_or(FlowError::UnknownSendReservation(reservation.id))?;
        let after = self.provisional_send_offset(reservation.stream);
        self.provisional_connection_sent = self
            .provisional_connection_sent
            .saturating_sub(before.saturating_sub(after));
        Ok(())
    }

    /// Atomically reserves and commits newly appended bytes.
    #[cfg(test)]
    pub fn reserve_send(&mut self, stream: StreamId, amount: u64) -> Result<(), FlowError> {
        validate_flow_value(amount)?;
        let end_offset = self.provisional_send_offset(stream).saturating_add(amount);
        let reservation = self.prepare_send(stream, end_offset)?;
        self.commit_send(reservation)
    }

    /// Checks a received exclusive stream end offset without changing flow state.
    pub fn check_receive(
        &self,
        stream: StreamId,
        end_offset: u64,
        final_size: bool,
    ) -> Result<(), FlowError> {
        validate_flow_value(end_offset)?;
        let state = self
            .streams
            .get(&stream)
            .ok_or(FlowError::StreamNotFound(stream))?;
        if end_offset > state.receive.maximum {
            return Err(FlowError::StreamReceiveLimit {
                stream,
                attempted: end_offset,
                maximum: state.receive.maximum,
            });
        }

        let provisional_used = self.provisional_receive_offset(stream);
        let known_final = state.final_size.or_else(|| {
            self.pending_receives
                .values()
                .find(|pending| pending.stream == stream && pending.final_size)
                .map(|pending| pending.end_offset)
        });
        if let Some(known) = known_final {
            if final_size && known != end_offset || end_offset > known {
                return Err(FlowError::FinalSizeChanged { stream });
            }
        }
        if final_size && end_offset < provisional_used {
            return Err(FlowError::FinalSizeSmallerThanReceived { stream });
        }

        let increment = end_offset.saturating_sub(provisional_used);
        let attempted = self
            .provisional_connection_received()
            .saturating_add(increment);
        if attempted > self.connection_receive.maximum || attempted > VARINT_MAX {
            return Err(FlowError::ConnectionReceiveLimit {
                attempted,
                maximum: self.connection_receive.maximum,
            });
        }
        Ok(())
    }

    pub fn prepare_receive(
        &mut self,
        stream: StreamId,
        end_offset: u64,
        final_size: bool,
    ) -> Result<ReceiveReservation, FlowError> {
        self.check_receive(stream, end_offset, final_size)?;
        let new_bytes = end_offset.saturating_sub(self.provisional_receive_offset(stream));
        let id = self.allocate_reservation_id()?;
        self.pending_receives.insert(
            id,
            PendingReceive {
                stream,
                end_offset,
                final_size,
            },
        );
        self.provisional_connection_received = self
            .provisional_connection_received
            .saturating_add(new_bytes);
        Ok(ReceiveReservation {
            id,
            stream,
            end_offset,
            final_size,
            new_bytes,
        })
    }

    pub fn commit_receive(&mut self, reservation: ReceiveReservation) -> Result<(), FlowError> {
        let pending = self
            .pending_receives
            .remove(&reservation.id)
            .ok_or(FlowError::UnknownReceiveReservation(reservation.id))?;
        let state = self
            .streams
            .get_mut(&pending.stream)
            .ok_or(FlowError::StreamNotFound(pending.stream))?;
        let increment = state.receive_to(pending.end_offset, pending.final_size)?;
        self.connection_receive.used = self.connection_receive.used.saturating_add(increment);
        Ok(())
    }

    pub fn cancel_receive(&mut self, reservation: ReceiveReservation) -> Result<(), FlowError> {
        let before = self.provisional_receive_offset(reservation.stream);
        self.pending_receives
            .remove(&reservation.id)
            .ok_or(FlowError::UnknownReceiveReservation(reservation.id))?;
        let after = self.provisional_receive_offset(reservation.stream);
        self.provisional_connection_received = self
            .provisional_connection_received
            .saturating_sub(before.saturating_sub(after));
        Ok(())
    }

    /// Records the largest received stream offset. Retransmitted or overlapping
    /// bytes do not consume connection-level credit a second time.
    pub fn receive_stream(
        &mut self,
        stream: StreamId,
        end_offset: u64,
        final_size: bool,
    ) -> Result<(), FlowError> {
        let reservation = self.prepare_receive(stream, end_offset, final_size)?;
        self.commit_receive(reservation)
    }

    pub fn consume_connection(&mut self, amount: u64) -> Result<Option<FlowAction>, FlowError> {
        Ok(self
            .connection_receive
            .consume(amount)?
            .map(FlowAction::SendMaxData))
    }

    pub fn consume_stream(
        &mut self,
        stream: StreamId,
        amount: u64,
    ) -> Result<Option<FlowAction>, FlowError> {
        let state = self
            .streams
            .get_mut(&stream)
            .ok_or(FlowError::StreamNotFound(stream))?;
        Ok(state
            .receive
            .consume(amount)?
            .map(|maximum| FlowAction::SendMaxStreamData { stream, maximum }))
    }

    pub fn consume_reset(&mut self, stream: StreamId) -> Result<Option<FlowAction>, FlowError> {
        let state = self
            .streams
            .get(&stream)
            .ok_or(FlowError::StreamNotFound(stream))?;
        let amount = state.receive.used.saturating_sub(state.receive.consumed);
        let connection = self.consume_connection(amount)?;
        self.streams
            .get_mut(&stream)
            .ok_or(FlowError::StreamNotFound(stream))?
            .receive
            .consume(amount)?;
        Ok(connection)
    }

    pub fn take_connection_update(&mut self) -> Option<FlowAction> {
        self.connection_receive
            .take_update()
            .map(FlowAction::SendMaxData)
    }

    pub fn take_stream_update(&mut self, stream: StreamId) -> Option<FlowAction> {
        self.streams
            .get_mut(&stream)
            .and_then(|state| state.receive.take_update())
            .map(|maximum| FlowAction::SendMaxStreamData { stream, maximum })
    }

    #[cfg(test)]
    pub fn take_scheduled_updates(&mut self) -> Vec<FlowAction> {
        let mut actions = Vec::new();
        if let Some(maximum) = self.connection_receive.take_update() {
            actions.push(FlowAction::SendMaxData(maximum));
        }
        for (stream, state) in &mut self.streams {
            if let Some(maximum) = state.receive.take_update() {
                actions.push(FlowAction::SendMaxStreamData {
                    stream: *stream,
                    maximum,
                });
            }
        }
        actions
    }

    fn allocate_reservation_id(&mut self) -> Result<u64, FlowError> {
        let id = self.next_reservation_id;
        self.next_reservation_id = self
            .next_reservation_id
            .checked_add(1)
            .ok_or(FlowError::ReservationIdExhausted)?;
        Ok(id)
    }

    fn provisional_send_offset(&self, stream: StreamId) -> u64 {
        let committed = self.streams.get(&stream).map_or(0, |state| state.sent);
        self.pending_sends
            .values()
            .filter(|(pending_stream, _)| *pending_stream == stream)
            .map(|(_, end_offset)| *end_offset)
            .fold(committed, cmp::max)
    }

    fn provisional_connection_sent(&self) -> u64 {
        self.provisional_connection_sent
    }

    fn provisional_receive_offset(&self, stream: StreamId) -> u64 {
        let committed = self
            .streams
            .get(&stream)
            .map_or(0, |state| state.receive.used);
        self.pending_receives
            .values()
            .filter(|pending| pending.stream == stream)
            .map(|pending| pending.end_offset)
            .fold(committed, cmp::max)
    }

    fn provisional_connection_received(&self) -> u64 {
        self.provisional_connection_received
    }
}

fn validate_flow_value(value: u64) -> Result<(), FlowError> {
    if value > VARINT_MAX {
        Err(FlowError::ValueOutOfRange(value))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    fn v4(port: u16) -> NetworkAddress {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)).into()
    }

    fn cid(byte: u8) -> ConnectionId {
        ConnectionId::for_new_connection_id(vec![byte; 8]).unwrap()
    }

    fn token(byte: u8) -> [u8; STATELESS_RESET_TOKEN_LEN] {
        [byte; STATELESS_RESET_TOKEN_LEN]
    }

    #[test]
    fn network_address_round_trips_v4_and_v6_metadata() {
        let v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 443));
        assert_eq!(SocketAddr::from(NetworkAddress::from(v4)), v4);
        let v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8443, 7, 4));
        let address = NetworkAddress::from(v6);
        assert_eq!(SocketAddr::from(address), v6);
        assert_eq!(address.port(), 8443);
    }

    #[test]
    fn server_path_enforces_and_lifts_anti_amplification() {
        let mut path = PathState::new(
            PathId::new(1),
            v4(443),
            v4(1000),
            Role::Server,
            false,
            PmtuState::new(1200, 1500).unwrap(),
        );
        path.receive(100);
        path.record_sent(300).unwrap();
        assert_eq!(path.send_allowance(), 0);
        assert_eq!(
            path.record_sent(1),
            Err(PathError::AntiAmplificationLimit {
                attempted: 1,
                allowance: 0
            })
        );
        path.start_validation(*b"12345678", Duration::from_millis(10))
            .unwrap();
        assert_eq!(
            path.receive_response(*b"badtoken"),
            Err(PathError::ChallengeMismatch)
        );
        assert_eq!(
            path.receive_response(*b"12345678"),
            Ok(PathAction::PathValidated(PathId::new(1)))
        );
        assert_eq!(path.send_allowance(), u64::MAX);
    }

    #[test]
    fn client_path_is_not_amplification_limited() {
        let mut path = PathState::new(
            PathId::new(0),
            v4(1),
            v4(2),
            Role::Client,
            false,
            PmtuState::new(1200, 1200).unwrap(),
        );
        path.record_sent(usize::MAX).unwrap();
        assert_eq!(path.validation, PathValidationState::Validated);
    }

    #[test]
    fn path_manager_signals_migration_and_requires_validation() {
        let mut paths = PathManager::new(Role::Server, v4(443), v4(1), true, 1280, 1500).unwrap();
        let (candidate, signal) = paths.observe_remote(v4(443), v4(2)).unwrap();
        assert_eq!(
            signal,
            Some(PathAction::PeerMigrationDetected {
                previous: PathId::new(0),
                candidate
            })
        );
        assert_eq!(
            paths.activate(candidate),
            Err(PathError::CannotActivateUnvalidatedPath(candidate))
        );
        let path = paths.path_mut(candidate).unwrap();
        path.start_validation(*b"abcdefgh", Duration::from_millis(1))
            .unwrap();
        path.receive_response(*b"abcdefgh").unwrap();
        assert_eq!(
            paths.activate(candidate).unwrap(),
            Some(PathAction::ActivePathChanged {
                previous: PathId::new(0),
                current: candidate
            })
        );
    }

    #[test]
    fn path_manager_bounds_unvalidated_candidates() {
        let mut paths = PathManager::new(Role::Server, v4(443), v4(1), true, 1280, 1500).unwrap();
        for port in 2..=MAX_PATHS as u16 {
            paths.observe_remote(v4(443), v4(port)).unwrap();
        }
        assert_eq!(
            paths.observe_remote(v4(443), v4(9999)),
            Err(PathError::PathLimitExceeded)
        );
    }

    #[test]
    fn client_migration_path_still_requires_validation() {
        let mut paths = PathManager::new(Role::Client, v4(443), v4(1), true, 1280, 1500).unwrap();
        let (candidate, _) = paths.observe_remote(v4(443), v4(2)).unwrap();
        let path = paths.path(candidate).unwrap();
        assert_eq!(path.validation, PathValidationState::Unvalidated);
        assert_eq!(path.send_allowance(), u64::MAX);
        assert_eq!(
            paths.activate(candidate),
            Err(PathError::CannotActivateUnvalidatedPath(candidate))
        );
    }

    #[test]
    fn pmtu_uses_operational_probe_sizes_and_stops_after_loss() {
        let mut pmtu = PmtuState::new(1280, 1472).unwrap();
        assert_eq!(pmtu.next_probe_size(), Some(1350));
        pmtu.probe_sent(8, 1350, Duration::from_millis(10)).unwrap();
        assert_eq!(pmtu.probe_acked(8), Ok(1350));
        assert_eq!(pmtu.next_probe_size(), Some(1452));
        pmtu.probe_sent(9, 1452, Duration::from_millis(11)).unwrap();
        assert_eq!(pmtu.probe_lost(9), Ok(1452));
        assert_eq!(pmtu.current(), 1350);
        assert_eq!(pmtu.upper_bound(), 1451);
        assert_eq!(pmtu.next_probe_size(), None);
        assert_eq!(pmtu.probe_acked(99), Err(PathError::UnknownPmtuProbe(99)));
    }

    #[test]
    fn pmtu_reaches_ipv4_only_final_probe() {
        let mut pmtu = PmtuState::new(1280, 1472).unwrap();
        for (packet_number, size) in [(1, 1350), (2, 1452), (3, 1472)] {
            assert_eq!(pmtu.next_probe_size(), Some(size));
            pmtu.probe_sent(packet_number, size, Duration::ZERO)
                .unwrap();
            assert_eq!(pmtu.probe_acked(packet_number), Ok(size));
        }
        assert_eq!(pmtu.next_probe_size(), None);
    }

    #[test]
    fn peer_udp_limit_caps_pmtu_but_never_below_initial_size() {
        let mut pmtu = PmtuState::new(1200, 1452).unwrap();
        pmtu.cap_upper_bound(1300).unwrap();
        assert_eq!(pmtu.upper_bound(), 1300);
        assert_eq!(pmtu.next_probe_size(), Some(1280));
        assert!(pmtu.cap_upper_bound(1199).is_err());
        assert_eq!(pmtu.current(), 1200);
    }

    #[test]
    fn connection_id_lengths_are_validated() {
        assert!(ConnectionId::new(Vec::new()).unwrap().is_empty());
        assert_eq!(
            ConnectionId::for_new_connection_id(Vec::new()),
            Err(CidError::EmptyConnectionId)
        );
        assert_eq!(
            ConnectionId::new(vec![0; 21]),
            Err(CidError::ConnectionIdTooLong(21))
        );
    }

    #[test]
    fn peer_cids_apply_retire_prior_to_transactionally() {
        let mut store = PeerCidStore::new(3).unwrap();
        store.insert(0, 0, cid(0), token(0)).unwrap();
        store.insert(1, 0, cid(1), token(1)).unwrap();
        store.insert(2, 0, cid(2), token(2)).unwrap();
        let actions = store.insert(2, 2, cid(2), token(2)).unwrap();
        assert_eq!(
            actions,
            vec![CidAction::RetirePeer(0), CidAction::RetirePeer(1)]
        );
        assert!(store.get(0).unwrap().retired);
        assert_eq!(store.retire_prior_to(), 2);
        assert_eq!(
            store.insert(3, 4, cid(3), token(3)),
            Err(CidError::RetirePriorToExceedsSequence {
                retire_prior_to: 4,
                sequence: 3
            })
        );
        assert!(store.get(3).is_none());
    }

    #[test]
    fn peer_cids_reject_conflicts_duplicates_and_limit_overrun() {
        let mut store = PeerCidStore::new(2).unwrap();
        store.insert(0, 0, cid(0), token(0)).unwrap();
        assert!(store.insert(0, 0, cid(0), token(0)).unwrap().is_empty());
        assert_eq!(
            store.insert(0, 0, cid(1), token(1)),
            Err(CidError::ConflictingSequence(0))
        );
        assert_eq!(
            store.insert(1, 0, cid(0), token(1)),
            Err(CidError::DuplicateConnectionId)
        );
        store.insert(1, 0, cid(1), token(1)).unwrap();
        assert_eq!(
            store.insert(2, 0, cid(2), token(2)),
            Err(CidError::ActiveConnectionIdLimitExceeded { limit: 2 })
        );
    }

    #[test]
    fn peer_cids_reject_reset_token_reuse_with_initial_cid() {
        let mut store = PeerCidStore::new(2).unwrap();
        store.insert(0, 0, cid(0), token(0)).unwrap();
        store.install_initial_reset_token(token(9)).unwrap();
        assert_eq!(
            store.insert(1, 0, cid(1), token(9)),
            Err(CidError::DuplicateResetToken)
        );
    }

    #[test]
    fn peer_cids_assign_uniquely_and_match_reset_tokens() {
        let mut store = PeerCidStore::new(2).unwrap();
        store.insert(0, 0, cid(0), token(7)).unwrap();
        store.install_initial_reset_token(token(7)).unwrap();
        store.insert(1, 0, cid(1), token(8)).unwrap();
        assert_eq!(store.assign_to_path(PathId::new(1)).unwrap().sequence, 0);
        assert_eq!(store.assign_to_path(PathId::new(2)).unwrap().sequence, 1);
        assert!(store.matches_reset_token(&token(7)));
        assert!(store.matches_reset_token(&token(8)));
        assert!(!store.matches_reset_token(&[7; 15]));
        assert_eq!(store.retire(0), Err(CidError::ConnectionIdInUse(0)));
        store.release_path(PathId::new(1));
        store.retire(0).unwrap();
        assert!(!store.matches_reset_token(&token(7)));
    }

    #[test]
    fn rotating_peer_cid_retires_the_previous_assignment() {
        let mut store = PeerCidStore::new(2).unwrap();
        store.insert(0, 0, cid(0), token(0)).unwrap();
        store.insert(1, 0, cid(1), token(1)).unwrap();
        let path = PathId::new(1);
        store.assign_to_path(path).unwrap();
        let (retired, current) = store.rotate_path(path).unwrap();
        assert_eq!(retired, 0);
        assert_eq!(current.sequence, 1);
        assert!(store.get(0).unwrap().retired);
        assert_eq!(
            store.rotate_path(path),
            Err(CidError::ActiveConnectionIdLimitExceeded { limit: 2 })
        );
    }

    #[test]
    fn local_cids_obey_peer_limit_and_retire() {
        let mut store = LocalCidStore::new(2).unwrap();
        let first = store.issue(cid(1), token(1)).unwrap();
        assert!(matches!(first, CidAction::AdvertiseLocal(_)));
        store.issue(cid(2), token(2)).unwrap();
        assert_eq!(
            store.issue(cid(3), token(3)),
            Err(CidError::ActiveConnectionIdLimitExceeded { limit: 2 })
        );
        store.assign_to_path(PathId::new(1), 0).unwrap();
        assert_eq!(store.retire_from_peer(0), Ok(CidAction::LocalRetired(0)));
        assert!(store.get(0).unwrap().retired);
        store.issue(cid(3), token(3)).unwrap();
    }

    #[test]
    fn invalid_limits_and_varints_are_rejected() {
        assert!(matches!(
            PeerCidStore::new(1),
            Err(CidError::InvalidActiveConnectionIdLimit(1))
        ));
        assert!(matches!(
            FlowController::new(VARINT_MAX + 1, 10, 10),
            Err(FlowError::ValueOutOfRange(value)) if value == VARINT_MAX + 1
        ));
    }

    fn flow_controller() -> FlowController {
        let mut flow = FlowController::new(100, 100, 100).unwrap();
        flow.insert_stream(StreamFlowState::new(StreamId::new(0).unwrap(), 70, 80, 80).unwrap())
            .unwrap();
        flow.insert_stream(StreamFlowState::new(StreamId::new(4).unwrap(), 70, 80, 80).unwrap())
            .unwrap();
        flow
    }

    #[test]
    fn send_flow_control_is_transactional() {
        let mut flow = flow_controller();
        flow.reserve_send(StreamId::new(0).unwrap(), 60).unwrap();
        assert!(matches!(
            flow.reserve_send(StreamId::new(0).unwrap(), 20),
            Err(FlowError::StreamSendLimit { .. })
        ));
        flow.reserve_send(StreamId::new(4).unwrap(), 40).unwrap();
        assert!(matches!(
            flow.reserve_send(StreamId::new(4).unwrap(), 1),
            Err(FlowError::ConnectionSendLimit { .. })
        ));
        assert_eq!(flow.stream(StreamId::new(0).unwrap()).unwrap().sent(), 60);
    }

    #[test]
    fn canceled_send_reservation_restores_credit() {
        let mut flow = flow_controller();
        let stream = StreamId::new(0).unwrap();
        let reservation = flow.prepare_send(stream, 70).unwrap();
        assert_eq!(reservation.new_bytes(), 70);
        assert!(matches!(
            flow.check_send(StreamId::new(4).unwrap(), 31),
            Err(FlowError::ConnectionSendLimit { .. })
        ));
        assert_eq!(flow.connection_sent(), 0);

        flow.cancel_send(reservation).unwrap();
        flow.reserve_send(StreamId::new(4).unwrap(), 31).unwrap();
        assert_eq!(flow.connection_sent(), 31);
        assert_eq!(flow.stream(stream).unwrap().sent(), 0);
    }

    #[test]
    fn send_retransmission_does_not_consume_new_credit() {
        let mut flow = flow_controller();
        let stream = StreamId::new(0).unwrap();
        let initial = flow.prepare_send(stream, 60).unwrap();
        flow.commit_send(initial).unwrap();
        assert_eq!(flow.connection_sent(), 60);

        let retransmission = flow.prepare_send(stream, 40).unwrap();
        assert_eq!(retransmission.new_bytes(), 0);
        flow.commit_send(retransmission).unwrap();
        assert_eq!(flow.connection_sent(), 60);
        assert_eq!(flow.stream(stream).unwrap().sent(), 60);
    }

    #[test]
    fn receive_counts_only_new_highest_offsets() {
        let mut flow = flow_controller();
        flow.receive_stream(StreamId::new(0).unwrap(), 60, false)
            .unwrap();
        flow.receive_stream(StreamId::new(0).unwrap(), 40, false)
            .unwrap();
        flow.receive_stream(StreamId::new(4).unwrap(), 40, false)
            .unwrap();
        assert!(matches!(
            flow.receive_stream(StreamId::new(4).unwrap(), 41, false),
            Err(FlowError::ConnectionReceiveLimit { .. })
        ));
        assert_eq!(
            flow.stream(StreamId::new(4).unwrap())
                .unwrap()
                .receive
                .used(),
            40
        );
    }

    #[test]
    fn canceled_receive_reservation_restores_credit_and_final_size() {
        let mut flow = flow_controller();
        let stream = StreamId::new(0).unwrap();
        let reservation = flow.prepare_receive(stream, 70, true).unwrap();
        assert_eq!(reservation.new_bytes(), 70);
        assert!(matches!(
            flow.check_receive(StreamId::new(4).unwrap(), 31, false),
            Err(FlowError::ConnectionReceiveLimit { .. })
        ));
        assert_eq!(flow.connection_received(), 0);

        flow.cancel_receive(reservation).unwrap();
        flow.receive_stream(StreamId::new(4).unwrap(), 31, false)
            .unwrap();
        assert_eq!(flow.connection_received(), 31);
        assert_eq!(flow.stream(stream).unwrap().received(), 0);
        assert_eq!(flow.stream(stream).unwrap().final_size(), None);
    }

    #[test]
    fn receive_retransmission_does_not_consume_new_credit() {
        let mut flow = flow_controller();
        let stream = StreamId::new(0).unwrap();
        flow.receive_stream(stream, 60, false).unwrap();
        assert_eq!(flow.connection_received(), 60);

        let retransmission = flow.prepare_receive(stream, 40, false).unwrap();
        assert_eq!(retransmission.new_bytes(), 0);
        flow.commit_receive(retransmission).unwrap();
        assert_eq!(flow.connection_received(), 60);
        assert_eq!(flow.stream(stream).unwrap().received(), 60);
    }

    #[test]
    fn final_size_rules_are_enforced() {
        let mut flow = flow_controller();
        flow.receive_stream(StreamId::new(0).unwrap(), 40, true)
            .unwrap();
        assert!(matches!(
            flow.receive_stream(StreamId::new(0).unwrap(), 41, true),
            Err(FlowError::FinalSizeChanged { .. })
        ));
        assert!(matches!(
            flow.receive_stream(StreamId::new(0).unwrap(), 41, false),
            Err(FlowError::FinalSizeChanged { .. })
        ));
    }

    #[test]
    fn consumption_schedules_window_updates_once() {
        let mut flow = flow_controller();
        flow.receive_stream(StreamId::new(0).unwrap(), 60, false)
            .unwrap();
        assert_eq!(
            flow.consume_connection(30).unwrap(),
            Some(FlowAction::SendMaxData(130))
        );
        assert_eq!(
            flow.consume_stream(StreamId::new(0).unwrap(), 30).unwrap(),
            Some(FlowAction::SendMaxStreamData {
                stream: StreamId::new(0).unwrap(),
                maximum: 110
            })
        );
        assert_eq!(
            flow.take_scheduled_updates(),
            vec![
                FlowAction::SendMaxData(130),
                FlowAction::SendMaxStreamData {
                    stream: StreamId::new(0).unwrap(),
                    maximum: 110
                }
            ]
        );
        assert!(flow.take_scheduled_updates().is_empty());
    }

    #[test]
    fn hostile_arithmetic_does_not_panic() {
        let mut flow = FlowController::new(VARINT_MAX, VARINT_MAX, VARINT_MAX).unwrap();
        flow.insert_stream(
            StreamFlowState::new(
                StreamId::new(0).unwrap(),
                VARINT_MAX,
                VARINT_MAX,
                VARINT_MAX,
            )
            .unwrap(),
        )
        .unwrap();
        flow.reserve_send(StreamId::new(0).unwrap(), VARINT_MAX)
            .unwrap();
        assert!(flow.reserve_send(StreamId::new(0).unwrap(), 1).is_err());
        assert_eq!(
            flow.receive_stream(StreamId::new(0).unwrap(), u64::MAX, false),
            Err(FlowError::ValueOutOfRange(u64::MAX))
        );
    }
}
