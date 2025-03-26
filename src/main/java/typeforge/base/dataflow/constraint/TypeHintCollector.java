package typeforge.base.dataflow.constraint;

import typeforge.base.dataflow.expression.ParsedExpr;
import typeforge.base.dataflow.expression.NMAE;
import typeforge.base.dataflow.expression.NMAEManager;
import typeforge.base.dataflow.UnionFind;
import typeforge.base.dataflow.TFG.TypeFlowGraph;
import typeforge.base.dataflow.TFG.TypeRelationPath;
import typeforge.utils.Global;
import typeforge.utils.Logging;
import typeforge.utils.TCHelper;

import java.util.*;

public class TypeHintCollector {
    private final Set<TypeConstraint> typeConstraints;
    /* Map[SymbolExpr, Set[Skeleton]]: this is temp data structure before handling skeletons */
    private final Map<NMAE, Set<TypeConstraint>> exprToSkeletons_T;
    /* Map[SymbolExpr, Skeleton]: this is final data structure, very important */
    public final Map<NMAE, TypeConstraint> exprToSkeletonMap;

    /* SymbolExprs that have multiple skeletons */
    private final Set<NMAE> multiSkeletonExprs;

    private final NMAEManager exprManager;

    /** fields for handle conflict paths and nodes */
    public final Set<TypeRelationPath<NMAE>> evilPaths = new HashSet<>();
    public final Set<NMAE> evilNodes = new HashSet<>();
    public final Map<NMAE, Set<TypeFlowGraph.TypeFlowEdge>> evilNodeEdges = new HashMap<>();
    public final Set<NMAE> evilSource = new HashSet<>();
    public final Map<NMAE, Set<TypeFlowGraph.TypeFlowEdge>> evilSourceLCSEdges = new HashMap<>();
    public final Map<NMAE, Set<TypeFlowGraph.TypeFlowEdge>> evilSourceEndEdges = new HashMap<>();
    public final Set<NMAE> injuredNode = new HashSet<>();

    public TypeHintCollector(NMAEManager exprManager) {
        this.typeConstraints = new HashSet<>();
        this.exprToSkeletons_T = new HashMap<>();
        this.exprToSkeletonMap = new HashMap<>();
        this.multiSkeletonExprs = new HashSet<>();

        this.exprManager = exprManager;
    }

    /**
     * Some SymbolExprs may hold multiple Skeletons, we need to
     * merge and rebuild these Skeletons, and finally generate `exprToSkeletonMap`
     */
    public void mergeSkeletons() {
        // Generate expr To Skeletons
        for (var skt: typeConstraints) {
            for (var expr: skt.exprs) {
                exprToSkeletons_T.computeIfAbsent(expr, k -> new HashSet<>()).add(skt);
            }
        }

        for (var entry: exprToSkeletons_T.entrySet()) {
            var expr = entry.getKey();
            var skeletons = entry.getValue();
            if (skeletons.size() == 1) {
                exprToSkeletonMap.put(expr, skeletons.iterator().next());
                Logging.debug("SkeletonCollector", String.format("%s: S = 1", expr));
            }
            else if (skeletons.size() > 1) {
                Logging.debug("SkeletonCollector", String.format("%s: S > 1", expr));
                /* IF one SymbolExpr holds multi Skeletons, Create New Skeleton based on them */
                multiSkeletonExprs.add(expr);
                var constraints = new HashSet<Skeleton>();
                for (var skeleton: skeletons) {
                    constraints.addAll(skeleton.skeletons);
                }
                var newSkeleton = new TypeConstraint(constraints, expr);
                newSkeleton.hasMultiSkeleton = true;
                exprToSkeletonMap.put(expr, newSkeleton);
                skeletons.add(newSkeleton);
            }
        }

        // Remove multiSkeletonExprs from old skeletons
        for (var expr: multiSkeletonExprs) {
            for (var skt: exprToSkeletonMap.values()) {
                if (skt.hasMultiSkeleton) continue;
                var removed = skt.exprs.remove(expr);
                if (removed) {
                    Logging.debug("SkeletonCollector", String.format("%s is removed from skeleton %s", expr, skt));
                }
            }
        }

        // Merge Skeletons with multiConstraints by constraints' hashID
        var hashToSkeletons = new HashMap<Integer, Set<TypeConstraint>>();
        for (var expr: multiSkeletonExprs) {
            var skt = exprToSkeletonMap.get(expr);
            var hash = skt.getSkeletonsHash();
            hashToSkeletons.computeIfAbsent(hash, k -> new HashSet<>()).add(skt);
        }
        for (var entry: hashToSkeletons.entrySet()) {
            var skeletons = entry.getValue();
            if (skeletons.size() > 1) {
                var newSkeleton = new TypeConstraint();
                for (var skt: skeletons) {
                    newSkeleton.mergeConstraintFrom(skt);
                }
                for (var expr: newSkeleton.exprs) {
                    exprToSkeletonMap.put(expr, newSkeleton);
                }
            }
        }

        var SkeletonsToRemove = new HashSet<TypeConstraint>();
        // Checking Consistency
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            for (var e: skt.exprs) {
                if (exprToSkeletonMap.get(e) != skt) {
                    Logging.error("SkeletonCollector", String.format("Inconsistent Detected! %s", e));
                    System.exit(1);
                }
            }

            if (!skt.hasMultiSkeleton) {
                assert skt.skeletons.size() == 1;
                Logging.debug("SkeletonCollector", String.format("%s with single Constraint has Exprs: \n%s", skt.toString(), skt.exprs));
                Logging.debug("SkeletonCollector", String.format("Constraint: \n%s", skt.skeletons.iterator().next().dumpLayout(0)));
            } else {
                assert skt.skeletons.size() > 1;
                Logging.debug("SkeletonCollector", String.format("%s with multiple Constraints has Exprs: \n%s", skt.toString(), skt.exprs));
                for (var constraint: skt.skeletons) {
                    Logging.debug("SkeletonCollector", String.format("Constraint: \n%s", constraint.dumpLayout(0)));
                }
            }

            /* Remove Redundant Constraints */
            boolean emptySkeleton = true;
            for (var constraint: skt.skeletons) {
                if (!constraint.isEmpty()) {
                    emptySkeleton = false;
                    break;
                }
            }
            if (emptySkeleton) {
                Logging.debug("SkeletonCollector", String.format("Empty Skeleton Detected: %s", skt));
                SkeletonsToRemove.add(skt);
            }
        }

        for (var skt: SkeletonsToRemove) {
            typeConstraints.remove(skt);
            for (var expr: skt.exprs) {
                exprToSkeletonMap.remove(expr);
            }
        }
    }

    /**
     * For Skeletons with multiple constraints, we choose the most visited one as the final constraint.
     */
    public void handleFinalConstraint() {
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            if (!skt.hasMultiSkeleton) {
                skt.finalSkeleton = skt.skeletons.iterator().next();
            };

            int maxVisit = 0;
            Skeleton maxVisitConstraint = null;
            for (var con: skt.skeletons) {
                var curVisit = con.getAllFieldsAccessCount();
                if (curVisit > maxVisit) {
                    maxVisit = curVisit;
                    maxVisitConstraint = con;
                }
            }

            // TODO: should we merge Skeletons with same finalConstraint ?
            if (maxVisitConstraint != null) {
                skt.hasMultiSkeleton = false;
                skt.finalSkeleton = maxVisitConstraint;
                Logging.debug("SkeletonCollector", String.format("%s:\n%s", skt, skt.exprs));
                Logging.debug("SkeletonCollector", String.format("Choose the most visited constraint:\n%s", maxVisitConstraint.dumpLayout(0)));
            }
        }
    }

    /**
     * Build Relationships introduced by Struct Pointer Reference
     */
    public void handlePtrReference() {
        /* Build basic Reference Relationship */
        for (var expr: exprToSkeletonMap.keySet()) {
            if (!expr.isDereference()) {
                continue;
            }

            var parsed = ParsedExpr.parseFieldAccessExpr(expr);
            if (parsed.isEmpty()) continue;
            var parsedExpr = parsed.get();
            var base = parsedExpr.base;
            var offset = parsedExpr.offsetValue;

            if (exprToSkeletonMap.containsKey(base)) {
                var baseSkt = exprToSkeletonMap.get(base);
                baseSkt.addPtrReference(offset, exprToSkeletonMap.get(expr));
                baseSkt.ptrLevel.put(offset, 1);
            }
        }

        /* In rare cases, for some reason, there may be some multi-ple ptr reference or nested skeletons */
        handleMultiPtrReferenceTo();

        /* Handle MultiLevel Ptr Reference */
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            for (var offset: skt.finalPtrReference.keySet()) {
                var ptrEESkt = skt.finalPtrReference.get(offset);
                var ptrLevel = 1;
                while (ptrEESkt.isMultiLevelMidPtr()) {
                    ptrLevel++;
                    if (ptrEESkt == ptrEESkt.finalPtrReference.get(0L)) {
                        Logging.warn("SkeletonCollector", "Ptr Reference Loop Detected!");
                        break;
                    }
                    ptrEESkt = ptrEESkt.finalPtrReference.get(0L);
                }

                if (ptrLevel > 1) {
                    Logging.debug("SkeletonCollector", String.format("Ptr Level > 1,  = %d", ptrLevel));
                    skt.ptrLevel.put(offset, ptrLevel);
                    skt.finalPtrReference.put(offset, ptrEESkt);

                    /* For debug */
                    Logging.debug("SkeletonCollector", String.format("Ptr Reference at 0x%s -> %s", Long.toHexString(offset), ptrEESkt));
                    Logging.debug("SkeletonCollector", skt.exprs.toString());
                    Logging.debug("SkeletonCollector", skt.finalSkeleton.dumpLayout(0));
                    Logging.debug("SkeletonCollector", ptrEESkt.exprs.toString());
                    Logging.debug("SkeletonCollector", ptrEESkt.finalSkeleton.dumpLayout(0));
                } else {
                    Logging.debug("SkeletonCollector", "Ptr Level = 1");
                }
            }
        }

        /* Remove Ptr Reference which points to a multiLevelMidPtr */
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            if (skt.hasPtrReference()) {
                for (var offset: skt.finalPtrReference.keySet()) {
                    var ptrEE = skt.finalPtrReference.get(offset);
                    if (ptrEE.isMultiLevelMidPtr) {
                        skt.finalPtrReference.remove(offset);
                        skt.ptrLevel.remove(offset);
                        Logging.debug("SkeletonCollector", String.format("Remove multiLevel Mid Ptr: %s", ptrEE));
                    }
                }
            }
        }
    }

    /**
     * In Type Skeleton, some member may have conflict point to reference, we need to handle it.
     */
    public void handleMemberConflict() {
        var ptrSize = Global.currentProgram.getDefaultPointerSize();
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            List<Long> offsets = new ArrayList<>(skt.finalSkeleton.fieldAccess.keySet());
            Collections.sort(offsets);
            List<Long> removeCandidate = new ArrayList<>();
            for (int i = 0; i < offsets.size(); i++) {
                var offset = offsets.get(i);
                var aps = skt.finalSkeleton.fieldAccess.get(offset);

                long nextOffset = -1;
                if (i < offsets.size() - 1) {
                    nextOffset = offsets.get(i + 1);
                }

                if (skt.finalPtrReference.containsKey(offset)) {
                    if (nextOffset != -1 && (nextOffset - offset) < ptrSize) {
                        skt.finalPtrReference.remove(offset);
                        Logging.debug("SkeletonCollector", String.format("Found Conflict Member's Ptr Reference at 0x%s", Long.toHexString(offset)));
                    }
                } else {
                    var size = aps.mostAccessedDT.getLength();
                    if (nextOffset != -1 && (nextOffset - offset) < size) {
                        removeCandidate.add(offset);
                        Logging.debug("SkeletonCollector", String.format("Found Conflict Member at 0x%s", Long.toHexString(offset)));
                        Logging.debug("SkeletonCollector", String.format("MostAccessedDTSize = %d", size));
                        Logging.debug("SkeletonCollector", String.format("Next Offset = 0x%s", Long.toHexString(nextOffset)));
                    }
                }
            }

            for (var offset: removeCandidate) {
                skt.finalSkeleton.fieldAccess.remove(offset);
            }
        }
    }


    /**
     * Similar to `handleMemoryAlias`, if `*(a+0x8)` and `*(b+0x8)` has different Skeleton but `a` and `b` has same Skeleton.
     * We Consider `*(a+0x8)` and `*(b+0x8)` has same Skeleton and merge them.
     */
    public void handleTypeAlias() {
        /* initialize aliasMap using Skeleton's expressions */
        var aliasMap = new UnionFind<NMAE>();
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            aliasMap.initializeWithCluster(skt.exprs);
        }

        for (var expr: exprToSkeletonMap.keySet()) {
            if (expr.isDereference()) {
                parseAndSetTypeAlias(expr, aliasMap);
            }
        }
    }

    /**
     * Handle May Nesting Relationships between Skeletons
     * @param exprsAsArgument SymbolExpr that used as arguments in callSite.
     */
    public void handleNesting(Set<NMAE> exprsAsArgument) {
        /* Add MayNestedSkeleton */
        for (var expr: exprsAsArgument) {
            if (!exprToSkeletonMap.containsKey(expr)) continue;
            /* If expr is a SymbolExpr like `base + offset`, we seem it as a may nested expr */
            if (expr.hasBase() && expr.hasOffset() && expr.getOffset().isNoZeroConst()) {
                var base = expr.getBase();
                var offset = expr.getOffset().getConstant();
                if (exprToSkeletonMap.containsKey(base)) {
                    var baseSkt = exprToSkeletonMap.get(base);
                    baseSkt.mayNestedConstraint.computeIfAbsent(offset, k -> new HashSet<>())
                            .add(exprToSkeletonMap.get(expr));
                }
            }
        }

        /* Remove skeletons that should not be nested */
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            if (skt.hasNestedConstraint()) {
                var iterator = skt.mayNestedConstraint.keySet().iterator();
                while (iterator.hasNext()) {
                    var offset = iterator.next();
                    if (offset > skt.getSize()) {
                        iterator.remove();
                        Logging.debug("SkeletonCollector", "Offset larger than the size of the nester!");
                    } else {
                        var removeCandidates = new HashSet<TypeConstraint>();
                        for (var s: skt.mayNestedConstraint.get(offset)) {
                            if (s.isMultiLevelMidPtr || s.isPointerToPrimitive || skt == s) {
                                removeCandidates.add(s);
                            }
                        }
                        if (!removeCandidates.isEmpty()) {
                            skt.mayNestedConstraint.get(offset).removeAll(removeCandidates);
                            if (skt.mayNestedConstraint.get(offset).isEmpty()) {
                                iterator.remove();
                            }
                            Logging.debug("SkeletonCollector", String.format("Remove Unreasonable nested skeleton: %s", removeCandidates));
                        }
                    }
                }
            }
        }

        /* Handling mayNested Skeleton and build the finalNestedSkeleton */
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            for (var entry: skt.mayNestedConstraint.entrySet()) {
                var offset = entry.getKey();
                var nestedSkts = entry.getValue();
                TypeConstraint finalNestedCandidate = null;
                for (var nestedSkt: nestedSkts) {
                    tryPopulateNester(skt, offset, nestedSkt);
                    if (finalNestedCandidate == null) {
                        finalNestedCandidate = nestedSkt;
                    } else {
                        if (nestedSkt.variables.size() >= finalNestedCandidate.variables.size()) {
                            finalNestedCandidate = nestedSkt;
                        }
                    }
                }
                skt.finalNestedConstraint.put(offset, finalNestedCandidate);
                skt.updateNestedRange(offset, offset + (long) finalNestedCandidate.getSize());
            }
        }
    }

    public void handleMultiPtrReferenceTo() {
        /* Choose the most visited one as the final ReferenceTo constraint */
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            if (skt.hasMultiPtrReferenceTo()) {
                Logging.warn("SkeletonCollector", String.format("Multi Ptr Reference To Detected: \n%s", skt));
                for (var offset: skt.ptrReference.keySet()) {
                    var ptrEEs = skt.ptrReference.get(offset);
                    if (ptrEEs.size() > 1) {
                        Logging.warn("SkeletonCollector", String.format("At 0x%s: %s", Long.toHexString(offset), ptrEEs));
                        TypeConstraint chosenSkt = null;
                        for (var ptrEE: ptrEEs) {
                            if (chosenSkt == null) {
                                chosenSkt = ptrEE;
                            } else {
                                if (ptrEE.exprs.size() > chosenSkt.exprs.size()) {
                                    chosenSkt = ptrEE;
                                }
                            }
                        }
                        skt.finalPtrReference.put(offset, chosenSkt);
                    } else {
                        skt.finalPtrReference.put(offset, ptrEEs.iterator().next());
                    }
                }
            }
            else {
                for (var offset: skt.ptrReference.keySet()) {
                    var ptrEE = skt.ptrReference.get(offset).iterator().next();
                    skt.finalPtrReference.put(offset, ptrEE);
                }
            }
        }
    }

    /**
     * This method should be called after all skeletons are successfully handled.
     */
    public void handleDecompilerInferredTypes() {
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            for (var expr: skt.exprs) {
                if (expr.isVariable()) {
                    // var inferredType = exprManager.getInferredType(expr);
                    // inferredType.ifPresent(skt::updateDecompilerInferredTypes);
                }
            }
        }
    }

    /**
     * Mark MayPrimitiveType for Skeletons and handle reference and nested mayPrimitiveType skeletons.
     */
    public void handleUnreasonableSkeleton() {
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            if (skt.isMultiLevelMidPtr()) {
                Logging.debug("SkeletonCollector", "Multi Level Mid Ptr Skeleton: " + skt);
                skt.isMultiLevelMidPtr = true;
            } else if (skt.isIndependent() && skt.hasOneField() &&
                    !skt.decompilerInferredTypesHasComposite() &&
                    (skt.finalSkeleton.fieldAccess.get(0L) != null)) {
                /* These types are considered as pointers to primitive types and no need to assess and ranking */
                Logging.debug("SkeletonCollector", "Pointer to Primitive Detected: " + skt);
                var aps = skt.finalSkeleton.fieldAccess.get(0L);
                skt.setPrimitiveType(aps.mostAccessedDT);
            }
        }
    }


    public void handleAPSets() {
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            for (var offset: skt.finalSkeleton.fieldAccess.keySet()) {
                var APSet = skt.finalSkeleton.fieldAccess.get(offset);
                APSet.postHandle();
            }
        }
    }


    private void tryPopulateNester(TypeConstraint nester, Long nestStartOffset, TypeConstraint nestee) {
        for (var offset: nestee.finalSkeleton.fieldAccess.keySet()) {
            var nesterOffset = nestStartOffset + offset;
            var nesterAPS = nester.finalSkeleton.fieldAccess.get(nesterOffset);
            var nesteeAPS = nestee.finalSkeleton.fieldAccess.get(offset);

            if (nesterAPS == null) {
                nester.finalSkeleton.fieldAccess.put(nesterOffset, nesteeAPS);
            } else if (nesterAPS.maxDTSize >= nesteeAPS.maxDTSize) {
                nesterAPS.update(nesteeAPS);
            }
        }

        for (var offset: nestee.finalPtrReference.keySet()) {
            var nesterOffset = nestStartOffset + offset;
            var nesteePtrRef = nestee.finalPtrReference.get(offset);
            nester.finalPtrReference.putIfAbsent(nesterOffset, nesteePtrRef);
        }
    }


    private void parseAndSetTypeAlias(NMAE expr, UnionFind<NMAE> aliasMap) {
        // IMPORTANT: this algorithm is not perfect, it didn't run until a fixed point is reached.
        // So UnionFind may cause some inconsistency problem.
        var parsed = ParsedExpr.parseFieldAccessExpr(expr);
        if (parsed.isEmpty()) { return; }
        var parsedExpr = parsed.get();
        var base = parsedExpr.base;
        var offset = parsedExpr.offsetValue;
        if (base == null) { return; }

        if (parsedExpr.base.isDereference()) {
            parseAndSetTypeAlias(parsedExpr.base, aliasMap);
        }

        if (!aliasMap.contains(base)) {
            return;
        }

        for (var alias: aliasMap.getCluster(base)) {
            var res = exprManager.getFieldExprsByOffset(alias, offset);
            if (res.isEmpty()) { continue; }
            var fieldExprs = res.get();
            for (var e: fieldExprs) {
                if (aliasMap.contains(e) && aliasMap.contains(expr)) {
                    if (aliasMap.connected(e, expr)) continue;

                    var skt1 = exprToSkeletonMap.get(e);
                    var skt2 = exprToSkeletonMap.get(expr);
                    if (skt1 != skt2) {
                        // TODO: also checking polyTypes.
                        if (twoSkeletonsConflict(skt1, skt2)) {
                            Logging.warn("SkeletonCollector", String.format("Conflict Type Alias: %s <--> %s", e, expr));
                            continue;
                        }

                        Logging.debug("SkeletonCollector", String.format("Type Alias Detected: %s <--> %s", e, expr));
                        aliasMap.union(e, expr);
                        Optional<TypeConstraint> mergedRes;
                        TypeConstraint newTypeConstraint = null;

                        if (skt1.hasMultiSkeleton && skt2.hasMultiSkeleton) {
                            Logging.warn("SkeletonCollector", "all have multi constraints");
                            mergedRes = TypeConstraint.mergeConstraints(skt1, skt2, false);
                        } else if (skt1.hasMultiSkeleton || skt2.hasMultiSkeleton) {
                            Logging.warn("SkeletonCollector", "one has multi constraints");
                            mergedRes = TypeConstraint.mergeConstraints(skt1, skt2, false);
                        } else {
                            Logging.warn("SkeletonCollector", "none has multi constraints");
                            mergedRes = TypeConstraint.mergeConstraints(skt1, skt2, true);
                        }

                        if (mergedRes.isPresent()) {
                            newTypeConstraint = mergedRes.get();
                            Logging.debug("SkeletonCollector", String.format("New Merged %s from type Alias.", newTypeConstraint));
                            Logging.debug("SkeletonCollector", newTypeConstraint.exprs.toString());
                            /* update exprToSkeletonMap */
                            for (var e1: newTypeConstraint.exprs) {
                                exprToSkeletonMap.put(e1, newTypeConstraint);
                            }
                        } else {
                            Logging.warn("SkeletonCollector", String.format("Failed to merge skeletons of %s and %s", e, expr));
                        }
                    }
                }
            }
        }
    }

    private boolean twoSkeletonsConflict(TypeConstraint skt1, TypeConstraint skt2) {
        // Only check if both skeletons have single constraint
        if (!skt1.hasMultiSkeleton && !skt2.hasMultiSkeleton) {
            return TCHelper.checkFieldOverlap(skt1.skeletons.iterator().next(), skt2.skeletons.iterator().next());
        } else {
            return false;
        }
    }

    public void addSkeleton(TypeConstraint skt) {
        typeConstraints.add(skt);
    }

    public void updateEvilPaths(Set<TypeRelationPath<NMAE>> evilPaths) {
        this.evilPaths.addAll(evilPaths);
    }

    public void updateEvilSource(Set<NMAE> evilSource,
                                  Map<NMAE, Set<TypeFlowGraph.TypeFlowEdge>> evilSourceLCSEdges,
                                  Map<NMAE, Set<TypeFlowGraph.TypeFlowEdge>> evilSourceEndEdges) {
        this.evilSource.addAll(evilSource);
        this.evilSourceLCSEdges.putAll(evilSourceLCSEdges);
        this.evilSourceEndEdges.putAll(evilSourceEndEdges);
    }

    public void updateEvilNodes(Set<NMAE> evilNodes,
                                Map<NMAE, Set<TypeFlowGraph.TypeFlowEdge>> evilNodeEdges) {
        this.evilNodes.addAll(evilNodes);
        this.evilNodeEdges.putAll(evilNodeEdges);
    }
}
