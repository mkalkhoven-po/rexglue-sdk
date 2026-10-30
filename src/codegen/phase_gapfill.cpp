/**
 * @file        codegen/phase_gapfill.cpp
 * @brief       GapFill phase: find uncovered code regions and register them as functions
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 */

#include "ppc/instruction.h"

#include <unordered_set>

#include <rex/codegen/phases.h>
#include "phase_helpers.h"

#include <rex/logging.h>

#include "codegen_logging.h"
#include <rex/memory/utils.h>

#include <algorithm>

#include <ppc.h>

using rex::codegen::ppc::decode_instruction;
using rex::codegen::ppc::Opcode;
using rex::memory::load_and_swap;

namespace rex::codegen {

namespace {

//=============================================================================
// GapFill to register uncovered code regions
//=============================================================================

// Split a code region into function segments based on terminators (blr, tail calls).
std::vector<CodeRegion> splitRegionOnTerminators(
    const CodeRegion& region, const BinaryView& binary,
    const std::unordered_set<uint32_t>& knownCallables) {
  std::vector<CodeRegion> segments;
  uint32_t segmentStart = region.start;

  for (uint32_t addr = region.start; addr < region.end; addr += 4) {
    const uint8_t* data = binary.translate(addr);
    if (!data)
      break;

    uint32_t raw = load_and_swap<uint32_t>(data);
    auto decoded = decode_instruction(addr, raw);
    bool shouldSplit = false;
    const char* reason = nullptr;

    // Check for terminators
    if (decoded.is_return()) {
      shouldSplit = true;
      reason = "blr";
    } else if (decoded.opcode == Opcode::b && decoded.branch_target.has_value()) {
      uint32_t target = decoded.branch_target.value();
      // Don't split on tail recursion (branch to own segment start)
      if (target != segmentStart && knownCallables.contains(target)) {
        shouldSplit = true;
        reason = "tail call";
      }
    }

    if (shouldSplit) {
      uint32_t segmentEnd = addr + 4;
      if (segmentEnd > segmentStart) {
        segments.push_back({segmentStart, segmentEnd});
        REXCODEGEN_TRACE("GapFill: split segment 0x{:08X}-0x{:08X} ({} at 0x{:08X})", segmentStart,
                         segmentEnd, reason, addr);
      }
      segmentStart = segmentEnd;
    }
  }

  // Handle remaining code after last terminator
  if (segmentStart < region.end) {
    segments.push_back({segmentStart, region.end});
  }

  return segments;
}

// Check if address looks like exception handler data (handler ptr + rdata ptr)
bool looksLikeExceptionData(const BinaryView& binary, const FunctionGraph& graph, uint32_t addr) {
  const uint8_t* data = binary.translate(addr);
  if (!data)
    return false;

  // Exception handler data pattern:
  // [addr+0]: pointer to __C_specific_handler (entry point)
  // [addr+4]: pointer to scope table in .rdata
  uint32_t firstDword = load_and_swap<uint32_t>(data);
  uint32_t secondDword = load_and_swap<uint32_t>(data + 4);

  // Check if first dword is a known entry point (like __C_specific_handler)
  if (!graph.isEntryPoint(firstDword)) {
    return false;
  }

  // Check if second dword points to .rdata section
  auto* rdataSection = binary.findSectionByName(".rdata");
  if (!rdataSection)
    return false;

  uint32_t rdataStart = rdataSection->baseAddress;
  uint32_t rdataEnd = rdataStart + rdataSection->size;

  if (secondDword >= rdataStart && secondDword < rdataEnd) {
    REXCODEGEN_TRACE(
        "GapFill: 0x{:08X} looks like exception data (handler=0x{:08X}, scope=0x{:08X}), skipping",
        addr, firstDword, secondDword);
    return true;
  }

  return false;
}

size_t gapFillCodeRegions(CodegenContext& ctx, std::unordered_set<uint32_t>& attempted,
                          std::vector<uint32_t>& created) {
  REXCODEGEN_TRACE("Analyze: checking for uncovered code regions...");

  auto& graph = ctx.graph;
  auto& binary = ctx.binary();
  auto& scan = ctx.scan;

  // Build set of known callables for tail call detection
  std::unordered_set<uint32_t> knownCallables;
  for (const auto& [addr, node] : graph.functions()) {
    knownCallables.insert(addr);
  }

  size_t gapsFound = 0;
  size_t segmentsCreated = 0;

  for (const auto& region : scan.codeRegions) {
    // Split region on terminators (blr, tail calls), then check each segment
    auto segments = splitRegionOnTerminators(region, binary, knownCallables);

    for (const auto& segment : segments) {
      // A segment only ends at blr or a direct tail call, so it can begin with one or
      // more known functions (e.g. ones ending in an indirect bctr tail call) and still
      // hold uncovered code after them. Skip past the known functions instead of
      // discarding the whole segment.
      uint32_t start = segment.start;
      bool afterImport = false;
      while (start < segment.end) {
        const FunctionNode* owner = graph.isEntryPoint(start) ? graph.getFunction(start)
                                                              : graph.getFunctionContaining(start);
        if (owner) {
          // The declared size is only trusted for CONFIG/PDATA (as in
          // FunctionNode::containsAddress); otherwise skip to the end of the last block.
          uint32_t ownerEnd = owner->end();
          if (owner->authority() != FunctionAuthority::CONFIG &&
              owner->authority() != FunctionAuthority::PDATA && !owner->blocks().empty()) {
            ownerEnd = 0;
            for (const auto& block : owner->blocks())
              ownerEnd = std::max(ownerEnd, block.end());
          }
          if (ownerEnd > start) {
            afterImport = owner->authority() == FunctionAuthority::IMPORT;
            start = ownerEnd;
            continue;
          }
        }
        // Skip short null padding between functions
        const uint8_t* data = binary.translate(start);
        if (data && load_and_swap<uint32_t>(data) == 0) {
          start += 4;
          continue;
        }
        break;
      }
      // Only try each gap start once, so absorbed gap functions are not re-created
      // on every pass.
      if (start >= segment.end || !attempted.insert(start).second)
        continue;

      // Imports are registered with a size of 4, so the rest of an import thunk table
      // (the following thunks and unused slots) would show up here; it isn't code.
      if (afterImport)
        continue;

      // Stop at the next known function entry
      uint32_t end = start + 4;
      while (end < segment.end && !graph.isEntryPoint(end))
        end += 4;

      // Skip if this looks like exception handler data (handler ptr + rdata ptr)
      if (looksLikeExceptionData(binary, graph, start))
        continue;

      uint32_t segmentSize = end - start;
      graph.addFunction(start, segmentSize, FunctionAuthority::GAP_FILL, false);
      created.push_back(start);

      REXCODEGEN_TRACE("GapFill: registered sub_{:08X} (0x{:08X}-0x{:08X}, {} bytes)", start, start,
                       end, segmentSize);
      segmentsCreated++;
    }

    gapsFound++;
  }

  if (segmentsCreated > 0) {
    REXCODEGEN_TRACE("Analyze: registered {} gap functions from {} regions", segmentsCreated,
                     gapsFound);
  } else {
    REXCODEGEN_TRACE("Analyze: no uncovered regions found");
  }
  return segmentsCreated;
}

//=============================================================================
// Cleanup absorbed GAP_FILL functions
//=============================================================================

// Checks every GAP_FILL function, or, when `candidates` is given (later GapFill passes,
// where all older gap functions were already checked), only the gap functions among the
// candidates and those that start inside a candidate's blocks.
void cleanupAbsorbedGapFills(CodegenContext& ctx,
                             const std::vector<uint32_t>* candidates = nullptr) {
  auto& graph = ctx.graph;
  std::vector<uint32_t> toRemove;

  std::vector<uint32_t> gapAddrs;
  if (candidates) {
    gapAddrs = *candidates;
    // A newly discovered function's blocks may run over older gap functions that
    // follow it; those must be checked too.
    for (uint32_t addr : *candidates) {
      auto it = graph.functions().find(addr);
      if (it == graph.functions().end())
        continue;
      uint32_t blockEnd = it->second->end();
      for (const auto& block : it->second->blocks())
        blockEnd = std::max(blockEnd, block.end());
      for (uint32_t a = addr + 4; a < blockEnd; a += 4) {
        if (graph.isEntryPoint(a))
          gapAddrs.push_back(a);
      }
    }
  } else {
    for (const auto& [addr, node] : graph.functions())
      gapAddrs.push_back(addr);
  }

  for (uint32_t addr : gapAddrs) {
    auto it = graph.functions().find(addr);
    if (it == graph.functions().end() || it->second->authority() != FunctionAuthority::GAP_FILL)
      continue;

    for (const auto& [otherAddr, otherNode] : graph.functions()) {
      if (otherAddr == addr)
        continue;
      if (!otherNode->containsAddress(addr))
        continue;

      // This GAP_FILL is inside another function's blocks
      if (otherNode->authority() != FunctionAuthority::GAP_FILL) {
        // Absorbed by higher authority - remove
        toRemove.push_back(addr);
        break;
      } else if (otherAddr < addr) {
        // Both GAP_FILL, other has lower address - it survives
        toRemove.push_back(addr);
        break;
      }
    }
  }

  for (uint32_t addr : toRemove) {
    graph.removeFunction(addr);
  }

  if (!toRemove.empty()) {
    REXCODEGEN_TRACE("Analyze: removed {} absorbed GAP_FILL functions", toRemove.size());
  }
}

}  // anonymous namespace

namespace phases {

VoidResult GapFill(CodegenContext& ctx, ProgressReporter* reporter) {
  (void)reporter;
  // A gap function's discovery can stop early (e.g. at an indirect bctr tail call),
  // leaving the rest of its segment uncovered. Repeat until no new gaps appear; each
  // pass skips past the blocks discovered in the previous one.
  constexpr int kMaxPasses = 1024;
  std::unordered_set<uint32_t> attempted;
  std::unordered_set<uint32_t> discoverAttempted;
  int pass = 0;
  for (; pass < kMaxPasses; ++pass) {
    std::vector<uint32_t> createdAddrs;
    size_t created = gapFillCodeRegions(ctx, attempted, createdAddrs);
    if (created == 0)
      break;

    // Discover blocks for the gap functions and for the call targets they register,
    // so the next pass sees the real extent of every function. A function that fails
    // discovery stays pending; it is tried only once.
    std::vector<uint32_t> discoveredAddrs;
    while (discoverPendingFunctions(ctx, buildKnownFunctions(ctx.graph, /*excludeGapFill=*/true),
                                    &discoverAttempted, &discoveredAddrs) > 0) {}
    REXCODEGEN_DEBUG("Analyze: GapFill pass {}: {} gap functions, {} discovered", pass + 1, created,
                     discoveredAddrs.size());

    // Any function discovered in this pass, not only a gap function, can absorb gap
    // functions.
    cleanupAbsorbedGapFills(ctx, pass == 0 ? nullptr : &discoveredAddrs);
  }
  if (pass == kMaxPasses)
    REXCODEGEN_WARN("Analyze: GapFill stopped after {} passes without converging", kMaxPasses);

  return Ok();
}

}  // namespace phases

}  // namespace rex::codegen
