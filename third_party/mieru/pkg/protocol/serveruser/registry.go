// Copyright (C) 2026  mieru authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package serveruser

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/enfein/mieru/v3/pkg/log"
)

const metadataLength = 32

type user struct {
	id         uint32
	name       string
	credential [sha256.Size]byte
	decryptor  *cipher.StatelessDecryptor
	policy     Policy
}

type Policy struct {
	name   string
	quotas []Quota
}

type Quota struct {
	days      int32
	megabytes int32
}

func (p Policy) Name() string { return p.name }

func (p Policy) Quotas() []Quota { return p.quotas }

func (q Quota) Days() int32 { return q.days }

func (q Quota) Megabytes() int32 { return q.megabytes }

type state struct {
	users []user
	cache *sourceUserCache
}

type Registry struct {
	users         atomic.Pointer[state]
	hintMandatory atomic.Bool
	stats         sourceUserCacheStats
}

type Source struct {
	key   [16]byte
	valid bool
}

type matchOrigin uint8

const (
	matchUnknown matchOrigin = iota
	matchCachedHint
	matchRegistryHint
	matchCachedFallback
	matchRegistryFallback
)

type discoveryResult struct {
	block             cipher.BlockCipher
	decryptedMetadata []byte
	userID            uint32
	userContext       cipher.BlockContext
	policy            Policy
	origin            matchOrigin
	generation        *state
	attempts          int
}

type Authentication struct {
	userID     uint32
	policy     Policy
	origin     matchOrigin
	generation *state
	source     Source
}

func (r discoveryResult) authentication(source Source) Authentication {
	return Authentication{
		userID:     r.userID,
		policy:     r.policy,
		origin:     r.origin,
		generation: r.generation,
		source:     source,
	}
}

func (a *Authentication) valid() bool {
	return a != nil && a.userID != 0 && a.generation != nil
}

func (a *Authentication) Valid() bool { return a.valid() }

func (a Authentication) Policy() Policy { return a.policy }

func (a *Authentication) recordAuthenticated() {
	if !a.valid() {
		return
	}
	generation := a.generation
	a.generation = nil
	if a.source.valid && generation.cache != nil {
		generation.cache.recordAuthenticated(a.source.key, a.userID)
	}
}

func (a *Authentication) Record() { a.recordAuthenticated() }

type sourceUserCache struct {
	table       atomic.Pointer[sourceUserCacheTable]
	stats       *sourceUserCacheStats
	tick        sourceUserCacheTickFunc
	bucketLocks [sourceUserCacheLockStripes]sync.Mutex
}

const (
	sourceUserCacheBucketCount = 4096
	sourceUserCacheWays        = 4
	sourceUserCacheUsers       = 16
	sourceUserCacheLockStripes = 256
)

type sourceUserCacheTable struct {
	buckets [sourceUserCacheBucketCount]sourceUserCacheBucket
}

type sourceUserCacheBucket struct {
	ways [sourceUserCacheWays]atomic.Pointer[sourceUserCacheEntry]
}

type sourceUserCacheEntry struct {
	key        [16]byte
	lastActive atomic.Uint32
	users      [sourceUserCacheUsers]atomic.Uint64
}

func newSourceUserCache(stats *sourceUserCacheStats) *sourceUserCache {
	return newSourceUserCacheWithTick(stats, sourceUserCacheCurrentTick)
}

func (c *sourceUserCache) loadTable() *sourceUserCacheTable {
	if c == nil {
		return nil
	}
	return c.table.Load()
}

func (c *sourceUserCache) retire() {
	if c != nil {
		c.table.Swap(nil)
	}
}

func (r *Registry) SetUsers(users map[string]*appctlpb.User) {
	state := buildState(users, &r.stats)
	old := r.users.Swap(state)
	if old != nil {
		old.cache.retire()
	}
}

func (r *Registry) SetHintMandatory(mandatory bool) {
	r.hintMandatory.Store(mandatory)
}

func (r *Registry) HasUsers() bool {
	state := r.users.Load()
	return state != nil && len(state.users) != 0
}

func (r *Registry) Discover(encryptedMetadata []byte, source Source, requireCurrent bool) (cipher.BlockCipher, []byte, Authentication, error) {
	result, err := discoverUser(&r.users, &r.hintMandatory, encryptedMetadata, source, requireCurrent, nil)
	if err != nil {
		return nil, nil, Authentication{}, err
	}
	result.block.SetBlockContext(result.userContext)
	return result.block, result.decryptedMetadata, result.authentication(source), nil
}

func (r *Registry) FlushMetrics() {
	r.stats.flushTo(registeredSourceUserCacheMetrics)
}

func buildState(users map[string]*appctlpb.User, stats *sourceUserCacheStats) *state {
	type inputUser struct {
		mapKey string
		user   *appctlpb.User
		name   string
	}

	inputs := make([]inputUser, 0, len(users))
	nameCounts := make(map[string]int, len(users))
	for mapKey, user := range users {
		name := ""
		if user != nil {
			name = user.GetName()
		}
		inputs = append(inputs, inputUser{mapKey: mapKey, user: user, name: name})
		nameCounts[name]++
	}

	sort.Slice(inputs, func(i, j int) bool {
		if inputs[i].name == inputs[j].name {
			return inputs[i].mapKey < inputs[j].mapKey
		}
		return inputs[i].name < inputs[j].name
	})

	compiled := make([]user, 0, len(inputs))
	loggedDuplicate := make(map[string]struct{})
	loggedEmptyName := false
	for _, input := range inputs {
		if input.name == "" {
			if !loggedEmptyName {
				log.Warnf("Skipping server user with empty name")
				loggedEmptyName = true
			}
			continue
		}
		if nameCounts[input.name] > 1 {
			if _, ok := loggedDuplicate[input.name]; !ok {
				log.Warnf("Skipping duplicate server user name %q", input.name)
				loggedDuplicate[input.name] = struct{}{}
			}
			continue
		}
		if len(input.name) > constant.MaxUserNameLen {
			log.Warnf("Skipping server user %q: name exceeds %d bytes", input.name, constant.MaxUserNameLen)
			continue
		}

		credential, err := buildCredential(input.user, input.name)
		if err != nil {
			log.Warnf("Skipping server user %q: %v", input.name, err)
			continue
		}
		decryptor, err := cipher.NewStatelessDecryptor(credential[:])
		if err != nil {
			log.Warnf("Skipping server user %q: failed to prepare credential", input.name)
			continue
		}
		compiled = append(compiled, user{
			id:         uint32(len(compiled) + 1),
			name:       input.name,
			credential: credential,
			decryptor:  decryptor,
			policy:     buildPolicy(input.user),
		})
	}

	return &state{
		users: compiled,
		cache: newSourceUserCache(stats),
	}
}

func buildCredential(user *appctlpb.User, name string) ([sha256.Size]byte, error) {
	var credential [sha256.Size]byte
	if user == nil {
		return credential, fmt.Errorf("user record is nil")
	}
	if user.GetHashedPassword() != "" {
		decoded, err := hex.DecodeString(user.GetHashedPassword())
		if err != nil {
			return credential, fmt.Errorf("hashed credential is not valid hexadecimal")
		}
		if len(decoded) != len(credential) {
			return credential, fmt.Errorf("hashed credential decodes to %d bytes, want %d", len(decoded), len(credential))
		}
		copy(credential[:], decoded)
		return credential, nil
	}
	if user.GetPassword() == "" {
		return credential, fmt.Errorf("credential is empty")
	}
	copy(credential[:], cipher.HashPassword([]byte(user.GetPassword()), []byte(name)))
	return credential, nil
}

func buildPolicy(user *appctlpb.User) Policy {
	policy := Policy{name: user.GetName()}
	if len(user.GetQuotas()) > 0 {
		policy.quotas = make([]Quota, 0, len(user.GetQuotas()))
		for _, quota := range user.GetQuotas() {
			policy.quotas = append(policy.quotas, Quota{
				days:      quota.GetDays(),
				megabytes: quota.GetMegabytes(),
			})
		}
	}
	return policy
}

func BuildPolicies(users map[string]*appctlpb.User) map[string]Policy {
	if len(users) == 0 {
		return nil
	}
	policies := make(map[string]Policy, len(users))
	for _, user := range users {
		if user == nil || user.GetName() == "" {
			continue
		}
		policies[user.GetName()] = buildPolicy(user)
	}
	return policies
}

func discoverUser(
	publisher *atomic.Pointer[state],
	hintMandatory *atomic.Bool,
	encryptedMetadata []byte,
	source Source,
	requireCurrent bool,
	afterAttempt func(*state),
) (discoveryResult, error) {
	if len(encryptedMetadata) < cipher.DefaultNonceSize {
		return discoveryResult{}, fmt.Errorf("encrypted metadata is shorter than nonce")
	}
	if publisher == nil {
		return discoveryResult{}, fmt.Errorf("server user publisher is nil")
	}

	for {
		state := publisher.Load()
		if state == nil || len(state.users) == 0 {
			return discoveryResult{}, fmt.Errorf("no server user found")
		}
		mandatory := false
		if hintMandatory != nil {
			mandatory = hintMandatory.Load()
		}

		result := tryState(state, encryptedMetadata, source, mandatory)
		if afterAttempt != nil {
			afterAttempt(state)
		}
		if requireCurrent && publisher.Load() != state {
			continue
		}
		if result.block == nil {
			return discoveryResult{}, fmt.Errorf("cipher.TryDecrypt() failed for all users")
		}
		if state.cache != nil && state.cache.stats != nil && (result.origin == matchCachedHint || result.origin == matchCachedFallback) {
			state.cache.stats.authenticationHits.Add(1)
		}
		result.generation = state
		return result, nil
	}
}

func tryState(state *state, encryptedMeta []byte, source Source, hintMandatory bool) discoveryResult {
	nonce := encryptedMeta[:cipher.DefaultNonceSize]
	var trialPlaintext [metadataLength]byte
	var cachedIDs [sourceUserCacheUsers]uint32
	cachedCount := 0
	if source.valid && state.cache != nil {
		cachedIDs, cachedCount = state.cache.lookup(source.key)
	}

	var attemptedCachedIDs [sourceUserCacheUsers]uint32
	attemptedCachedCount := 0
	attempts := 0

	for i := 0; i < cachedCount; i++ {
		user := userByID(state, cachedIDs[i])
		if user == nil || userIDWasAttempted(&attemptedCachedIDs, attemptedCachedCount, user.id) || !cipher.CheckUserFromHint([]byte(user.name), nonce) {
			continue
		}
		attemptedCachedCount = markUserIDAttempted(&attemptedCachedIDs, attemptedCachedCount, user.id)
		attempts++
		if result := tryUser(user, encryptedMeta, trialPlaintext[:0], true, matchCachedHint); result.block != nil {
			result.attempts = attempts
			return result
		}
	}

	if state.cache != nil && state.cache.stats != nil {
		state.cache.stats.fullFallbacks.Add(1)
	}
	for i := range state.users {
		user := &state.users[i]
		if userIDWasAttempted(&attemptedCachedIDs, attemptedCachedCount, user.id) || !cipher.CheckUserFromHint([]byte(user.name), nonce) {
			continue
		}
		attempts++
		if result := tryUser(user, encryptedMeta, trialPlaintext[:0], true, matchRegistryHint); result.block != nil {
			result.attempts = attempts
			return result
		}
	}

	if hintMandatory {
		return discoveryResult{attempts: attempts}
	}

	for i := 0; i < cachedCount; i++ {
		user := userByID(state, cachedIDs[i])
		if user == nil || userIDWasAttempted(&attemptedCachedIDs, attemptedCachedCount, user.id) {
			continue
		}
		if cipher.CheckUserFromHint([]byte(user.name), nonce) {
			continue
		}
		attemptedCachedCount = markUserIDAttempted(&attemptedCachedIDs, attemptedCachedCount, user.id)
		attempts++
		if result := tryUser(user, encryptedMeta, trialPlaintext[:0], false, matchCachedFallback); result.block != nil {
			result.attempts = attempts
			return result
		}
	}

	for i := range state.users {
		user := &state.users[i]
		if userIDWasAttempted(&attemptedCachedIDs, attemptedCachedCount, user.id) {
			continue
		}
		if cipher.CheckUserFromHint([]byte(user.name), nonce) {
			continue
		}
		attempts++
		if result := tryUser(user, encryptedMeta, trialPlaintext[:0], false, matchRegistryFallback); result.block != nil {
			result.attempts = attempts
			return result
		}
	}
	return discoveryResult{attempts: attempts}
}

func userIDWasAttempted(attempted *[sourceUserCacheUsers]uint32, count int, userID uint32) bool {
	for i := 0; i < count; i++ {
		if attempted[i] == userID {
			return true
		}
	}
	return false
}

func markUserIDAttempted(attempted *[sourceUserCacheUsers]uint32, count int, userID uint32) int {
	if count < len(attempted) && !userIDWasAttempted(attempted, count, userID) {
		attempted[count] = userID
		return count + 1
	}
	return count
}

func userByID(state *state, userID uint32) *user {
	if state == nil || userID == 0 || userID > uint32(len(state.users)) {
		return nil
	}
	user := &state.users[userID-1]
	if user.id != userID {
		return nil
	}
	return user
}

func tryUser(user *user, encryptedMeta, dst []byte, hintMatch bool, origin matchOrigin) discoveryResult {
	if hintMatch {
		cipher.ServerHintMatchDecrypt.Add(1)
	}
	block, plaintext, err := user.decryptor.TryDecrypt(encryptedMeta, dst)
	if err != nil {
		if hintMatch {
			cipher.ServerFailedHintMatchDecrypt.Add(1)
		}
		return discoveryResult{}
	}
	return discoveryResult{
		block:             block,
		decryptedMetadata: plaintext,
		userID:            user.id,
		userContext:       cipher.BlockContext{UserName: user.name},
		policy:            user.policy,
		origin:            origin,
	}
}
