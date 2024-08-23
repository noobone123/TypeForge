package blueprint.base.dataflow.skeleton;

import blueprint.base.dataflow.SymbolExpr.ParsedExpr;
import blueprint.base.dataflow.SymbolExpr.SymbolExpr;
import blueprint.base.dataflow.SymbolExpr.SymbolExprManager;
import blueprint.base.dataflow.UnionFind;
import blueprint.base.dataflow.typeRelation.TypeRelationGraph;
import blueprint.base.dataflow.typeRelation.TypeRelationPath;
import blueprint.utils.DataTypeHelper;
import blueprint.utils.Global;
import blueprint.utils.Logging;
import blueprint.utils.TCHelper;

import java.util.*;

public class SkeletonCollector {
    private final Set<Skeleton> skeletons;
    /* Map[SymbolExpr, Set[Skeleton]]: this is temp data structure before handling skeletons */
    private final Map<SymbolExpr, Set<Skeleton>> exprToSkeletons_T;
    /* Map[SymbolExpr, Skeleton]: this is final data structure, very important */
    public final Map<SymbolExpr, Skeleton> exprToSkeletonMap;

    /* SymbolExprs that have multiple skeletons */
    private final Set<SymbolExpr> multiSkeletonExprs;

    private final SymbolExprManager exprManager;

    /** fields for handle conflict paths and nodes */
    public final Set<TypeRelationPath<SymbolExpr>> evilPaths = new HashSet<>();
    public final Set<SymbolExpr> evilNodes = new HashSet<>();
    public final Map<SymbolExpr, Set<TypeRelationGraph.TypeRelationEdge>> evilNodeEdges = new HashMap<>();
    public final Set<SymbolExpr> evilSource = new HashSet<>();
    public final Map<SymbolExpr, Set<TypeRelationGraph.TypeRelationEdge>> evilSourceLCSEdges = new HashMap<>();
    public final Map<SymbolExpr, Set<TypeRelationGraph.TypeRelationEdge>> evilSourceEndEdges = new HashMap<>();
    public final Set<SymbolExpr> injuredNode = new HashSet<>();

    public SkeletonCollector(SymbolExprManager exprManager) {
        this.skeletons = new HashSet<>();
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
        for (var skt: skeletons) {
            for (var expr: skt.exprs) {
                exprToSkeletons_T.computeIfAbsent(expr, k -> new HashSet<>()).add(skt);
            }
        }

        for (var entry: exprToSkeletons_T.entrySet()) {
            var expr = entry.getKey();
            var skeletons = entry.getValue();
            if (skeletons.size() == 1) {
                exprToSkeletonMap.put(expr, skeletons.iterator().next());
                Logging.info("SkeletonCollector", String.format("%s: S = 1", expr));
            }
            else if (skeletons.size() > 1) {
                Logging.info("SkeletonCollector", String.format("%s: S > 1", expr));
                /* IF one SymbolExpr holds multi Skeletons, Create New Skeleton based on them */
                multiSkeletonExprs.add(expr);
                var constraints = new HashSet<TypeConstraint>();
                for (var skeleton: skeletons) {
                    constraints.addAll(skeleton.constraints);
                }
                var newSkeleton = new Skeleton(constraints, expr);
                newSkeleton.hasMultiConstraints = true;
                exprToSkeletonMap.put(expr, newSkeleton);
                skeletons.add(newSkeleton);
            }
        }

        // Remove multiSkeletonExprs from old skeletons
        for (var expr: multiSkeletonExprs) {
            for (var skt: exprToSkeletonMap.values()) {
                if (skt.hasMultiConstraints) continue;
                var removed = skt.exprs.remove(expr);
                if (removed) {
                    Logging.info("SkeletonCollector", String.format("%s is removed from skeleton %s", expr, skt));
                }
            }
        }

        // Merge Skeletons with multiConstraints by constraints' hashID
        var hashToSkeletons = new HashMap<Integer, Set<Skeleton>>();
        for (var expr: multiSkeletonExprs) {
            var skt = exprToSkeletonMap.get(expr);
            var hash = skt.getConstraintsHash();
            hashToSkeletons.computeIfAbsent(hash, k -> new HashSet<>()).add(skt);
        }
        for (var entry: hashToSkeletons.entrySet()) {
            var skeletons = entry.getValue();
            if (skeletons.size() > 1) {
                var newSkeleton = new Skeleton();
                for (var skt: skeletons) {
                    newSkeleton.mergeSkeletonFrom(skt);
                }
                for (var expr: newSkeleton.exprs) {
                    exprToSkeletonMap.put(expr, newSkeleton);
                }
            }
        }

        var SkeletonsToRemove = new HashSet<Skeleton>();
        // Checking Consistency
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            for (var e: skt.exprs) {
                if (exprToSkeletonMap.get(e) != skt) {
                    Logging.error("SkeletonCollector", String.format("Inconsistent Detected! %s", e));
                    System.exit(1);
                }
            }

            if (!skt.hasMultiConstraints) {
                assert skt.constraints.size() == 1;
                Logging.info("SkeletonCollector", String.format("%s with single Constraint has Exprs: \n%s", skt.toString(), skt.exprs));
                Logging.info("SkeletonCollector", String.format("Constraint: \n%s", skt.constraints.iterator().next().dumpLayout(0)));
            } else {
                assert skt.constraints.size() > 1;
                Logging.info("SkeletonCollector", String.format("%s with multiple Constraints has Exprs: \n%s", skt.toString(), skt.exprs));
                for (var constraint: skt.constraints) {
                    Logging.info("SkeletonCollector", String.format("Constraint: \n%s", constraint.dumpLayout(0)));
                }
            }

            /* Remove Redundant Constraints */
            boolean emptySkeleton = true;
            for (var constraint: skt.constraints) {
                if (!constraint.isEmpty()) {
                    emptySkeleton = false;
                    break;
                }
            }
            if (emptySkeleton) {
                Logging.info("SkeletonCollector", String.format("Empty Skeleton Detected: %s", skt));
                SkeletonsToRemove.add(skt);
            }
        }

        for (var skt: SkeletonsToRemove) {
            skeletons.remove(skt);
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
            if (!skt.hasMultiConstraints) {
                skt.finalConstraint = skt.constraints.iterator().next();
            };

            int maxVisit = 0;
            TypeConstraint maxVisitConstraint = null;
            for (var con: skt.constraints) {
                var curVisit = con.getAllFieldsAccessCount();
                if (curVisit > maxVisit) {
                    maxVisit = curVisit;
                    maxVisitConstraint = con;
                }
            }

            // TODO: should we merge Skeletons with same finalConstraint ?
            if (maxVisitConstraint != null) {
                skt.hasMultiConstraints = false;
                skt.finalConstraint = maxVisitConstraint;
                Logging.info("SkeletonCollector", String.format("%s:\n%s", skt, skt.exprs));
                Logging.info("SkeletonCollector", String.format("Choose the most visited constraint:\n%s", maxVisitConstraint.dumpLayout(0)));
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
                    Logging.info("SkeletonCollector", String.format("Ptr Level > 1,  = %d", ptrLevel));
                    skt.ptrLevel.put(offset, ptrLevel);
                    skt.finalPtrReference.put(offset, ptrEESkt);

                    /* For debug */
                    Logging.info("SkeletonCollector", String.format("Ptr Reference at 0x%s -> %s", Long.toHexString(offset), ptrEESkt));
                    Logging.info("SkeletonCollector", skt.exprs.toString());
                    Logging.info("SkeletonCollector", skt.finalConstraint.dumpLayout(0));
                    Logging.info("SkeletonCollector", ptrEESkt.exprs.toString());
                    Logging.info("SkeletonCollector", ptrEESkt.finalConstraint.dumpLayout(0));
                } else {
                    Logging.info("SkeletonCollector", "Ptr Level = 1");
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
            List<Long> offsets = new ArrayList<>(skt.finalConstraint.fieldAccess.keySet());
            Collections.sort(offsets);

            for (int i = 0; i < offsets.size(); i++) {
                var offset = offsets.get(i);
                var aps = skt.finalConstraint.fieldAccess.get(offset);

                long nextOffset = -1;
                if (i < offsets.size() - 1) {
                    nextOffset = offsets.get(i + 1);
                }

                if (skt.finalPtrReference.containsKey(offset)) {
                    if (nextOffset != -1 && (nextOffset - offset) < ptrSize) {
                        skt.finalPtrReference.remove(offset);
                        Logging.info("SkeletonCollector", String.format("Found Conflict Member's Ptr Reference at 0x%s", Long.toHexString(offset)));
                    }
                } else {
                    var maxDTSize = aps.maxDTSize;
                    if (nextOffset != -1 && (nextOffset - offset) < maxDTSize) {
                        Logging.info("SkeletonCollector", String.format("Found Conflict Member at 0x%s", Long.toHexString(offset)));
                        Logging.info("SkeletonCollector", String.format("MaxDTSize = %d", maxDTSize));
                        Logging.info("SkeletonCollector", String.format("Next Offset = 0x%s", Long.toHexString(nextOffset)));
                    }
                }
            }
        }
    }


    /**
     * Similar to `handleMemoryAlias`, if `*(a+0x8)` and `*(b+0x8)` has different Skeleton but `a` and `b` has same Skeleton.
     * We Consider `*(a+0x8)` and `*(b+0x8)` has same Skeleton and merge them.
     */
    public void handleTypeAlias() {
        /* initialize aliasMap using Skeleton's expressions */
        var aliasMap = new UnionFind<SymbolExpr>();
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
    public void handleNesting(Set<SymbolExpr> exprsAsArgument) {
        for (var expr: exprsAsArgument) {
            if (!exprToSkeletonMap.containsKey(expr)) continue;
            /* If expr is a SymbolExpr like `base + offset`, we seem it as a may nested expr */
            if (expr.hasBase() && expr.hasOffset() && expr.getOffset().isNoZeroConst()) {
                var base = expr.getBase();
                var offset = expr.getOffset().getConstant();
                if (exprToSkeletonMap.containsKey(base)) {
                    var baseSkt = exprToSkeletonMap.get(base);
                    baseSkt.mayNestedSkeleton.computeIfAbsent(offset, k -> new HashSet<>())
                            .add(exprToSkeletonMap.get(expr));
                }
            }
        }

        /* For Debugging */
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            for (var entry: skt.mayNestedSkeleton.entrySet()) {
                var offset = entry.getKey();
                var nestedSkts = entry.getValue();
                Logging.info("SkeletonCollector", String.format("%s has May Nested Skeletons at 0x%s: %s", skt, Long.toHexString(offset), nestedSkts));
                Logging.info("SkeletonCollector", skt.exprs.toString());
                Logging.info("SkeletonCollector", skt.finalConstraint.dumpLayout(0));
                for (var nestedSkt: nestedSkts) {
                    Logging.info("SkeletonCollector", nestedSkt.exprs.toString());
                    Logging.info("SkeletonCollector", nestedSkt.finalConstraint.dumpLayout(0));
                }
            }
        }
    }

    public void handleMultiPtrReferenceTo() {
        /* Choose the most visited one as the final ReferenceTo constraint */
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            if (skt.hasMultiPtrReferenceTo()) {
                Logging.warn("SkeletonCollector", String.format("Multi Ptr Reference To Detected: \n%s", skt));
                skt.dumpInfo();
                for (var offset: skt.ptrReference.keySet()) {
                    var ptrEEs = skt.ptrReference.get(offset);
                    if (ptrEEs.size() > 1) {
                        Logging.warn("SkeletonCollector", String.format("At 0x%s: %s", Long.toHexString(offset), ptrEEs));
                        Skeleton chosenSkt = null;
                        for (var ptrEE: ptrEEs) {
                            ptrEE.dumpInfo();
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

    public void handleMultiNestedSkeleton() {
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            if (skt.hasMultiNestedSkeleton()) {
                Logging.warn("SkeletonCollector", String.format("Multi Nested Skeleton Detected: \n%s", skt));
                skt.dumpInfo();
                for (var offset: skt.mayNestedSkeleton.keySet()) {
                    var nestedSkts = skt.mayNestedSkeleton.get(offset);
                    if (nestedSkts.size() > 1) {
                        Logging.warn("SkeletonCollector", String.format("At 0x%s: %s", Long.toHexString(offset), nestedSkts));
                        for (var nestedSkt: nestedSkts) {
                            nestedSkt.dumpInfo();
                        }
                    }
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
                    var inferredType = exprManager.getInferredType(expr);
                    inferredType.ifPresent(skt::updateDecompilerInferredTypes);
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
                Logging.info("SkeletonCollector", "Multi Level Mid Ptr Skeleton: " + skt);
                skt.isMultiLevelMidPtr = true;
            } else if (skt.isIndependent() && skt.hasOneField() &&
                    !skt.decompilerInferredTypesHasComposite() &&
                    (skt.finalConstraint.fieldAccess.get(0L) != null)) {
                /* These types are considered as pointers to primitive types and no need to assess and ranking */
                Logging.info("SkeletonCollector", "Pointer to Primitive Detected: " + skt);
                var aps = skt.finalConstraint.fieldAccess.get(0L);
                var pointerType = DataTypeHelper.getPointerDT(aps.mostAccessedDT, 1);
                if (pointerType == null) {
                    Logging.error("SkeletonCollector", "Failed to handle Pointer to Primitive");
                } else {
                    skt.setPrimitiveType(pointerType);
                }
            }
        }

        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            if (skt.hasPtrReference()) {
                for (var offset: skt.finalPtrReference.keySet()) {
                    var ptrEE = skt.finalPtrReference.get(offset);
                    if (ptrEE.isMultiLevelMidPtr) {
                        skt.finalPtrReference.remove(offset);
                        skt.ptrLevel.remove(offset);
                        Logging.info("SkeletonCollector", String.format("Remove multiLevel Mid Ptr: %s", ptrEE));
                    }
                }
            }

            if (skt.hasNestedSkeleton()) {
                var iterator = skt.mayNestedSkeleton.keySet().iterator();
                while (iterator.hasNext()) {
                    var offset = iterator.next();
                    var removeCandidates = new HashSet<Skeleton>();
                    for (var s: skt.mayNestedSkeleton.get(offset)) {
                        if (s.isMultiLevelMidPtr || s.isPointerToPrimitive || skt == s) {
                            removeCandidates.add(s);
                        }
                    }
                    if (!removeCandidates.isEmpty()) {
                        skt.mayNestedSkeleton.get(offset).removeAll(removeCandidates);
                        if (skt.mayNestedSkeleton.get(offset).isEmpty()) {
                            iterator.remove();
                        }
                        Logging.info("SkeletonCollector", String.format("Remove Unreasonable nested skeleton: %s", removeCandidates));
                    }
                }
            }
        }
    }


    public void handleAPSets() {
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            for (var offset: skt.finalConstraint.fieldAccess.keySet()) {
                var APSet = skt.finalConstraint.fieldAccess.get(offset);
                APSet.postHandle();
            }
        }
    }

    public void handleCodePtr(Set<SymbolExpr> exprsAsCodePtr) {
        for (var expr: exprsAsCodePtr) {
            if (expr.isDereference()) {
                var parsed = ParsedExpr.parseFieldAccessExpr(expr);
                if (parsed.isEmpty()) { return; }
                var base = parsed.get().base;
                var offset = parsed.get().offsetValue;
                // TODO: add attr to skeleton?
            }
        }
    }

    private void parseAndSetTypeAlias(SymbolExpr expr, UnionFind<SymbolExpr> aliasMap) {
        // IMPORTANT: this algorithm is not perfect, it didn't run until a fixed point is reached.
        // So UnionFind may cause some inconsistency problem.
        var parsed = ParsedExpr.parseFieldAccessExpr(expr);
        if (parsed.isEmpty()) { return; }
        var parsedExpr = parsed.get();
        var base = parsedExpr.base;
        var offset = parsedExpr.offsetValue;

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

                        Logging.info("SkeletonCollector", String.format("Type Alias Detected: %s <--> %s", e, expr));
                        aliasMap.union(e, expr);
                        Optional<Skeleton> mergedRes;
                        Skeleton newSkeleton = null;

                        if (skt1.hasMultiConstraints && skt2.hasMultiConstraints) {
                            Logging.warn("SkeletonCollector", "all have multi constraints");
                            mergedRes = Skeleton.mergeSkeletons(skt1, skt2, false);
                        } else if (skt1.hasMultiConstraints || skt2.hasMultiConstraints) {
                            Logging.warn("SkeletonCollector", "one has multi constraints");
                            mergedRes = Skeleton.mergeSkeletons(skt1, skt2, false);
                        } else {
                            Logging.warn("SkeletonCollector", "none has multi constraints");
                            mergedRes = Skeleton.mergeSkeletons(skt1, skt2, true);
                        }

                        if (mergedRes.isPresent()) {
                            newSkeleton = mergedRes.get();
                            Logging.info("SkeletonCollector", String.format("New Merged %s from type Alias.", newSkeleton));
                            Logging.info("SkeletonCollector", newSkeleton.exprs.toString());
                            /* update exprToSkeletonMap */
                            for (var e1: newSkeleton.exprs) {
                                exprToSkeletonMap.put(e1, newSkeleton);
                            }
                        } else {
                            Logging.warn("SkeletonCollector", String.format("Failed to merge skeletons of %s and %s", e, expr));
                        }
                    }
                }
            }
        }
    }

    private boolean twoSkeletonsConflict(Skeleton skt1, Skeleton skt2) {
        // Only check if both skeletons have single constraint
        if (!skt1.hasMultiConstraints && !skt2.hasMultiConstraints) {
            return TCHelper.checkFieldOverlap(skt1.constraints.iterator().next(), skt2.constraints.iterator().next());
        } else {
            return false;
        }
    }

    public void addSkeleton(Skeleton skt) {
        skeletons.add(skt);
    }

    public void updateEvilPaths(Set<TypeRelationPath<SymbolExpr>> evilPaths) {
        this.evilPaths.addAll(evilPaths);
    }

    public void updateEvilSource(Set<SymbolExpr> evilSource,
                                  Map<SymbolExpr, Set<TypeRelationGraph.TypeRelationEdge>> evilSourceLCSEdges,
                                  Map<SymbolExpr, Set<TypeRelationGraph.TypeRelationEdge>> evilSourceEndEdges) {
        this.evilSource.addAll(evilSource);
        this.evilSourceLCSEdges.putAll(evilSourceLCSEdges);
        this.evilSourceEndEdges.putAll(evilSourceEndEdges);
    }

    public void updateEvilNodes(Set<SymbolExpr> evilNodes,
                                Map<SymbolExpr, Set<TypeRelationGraph.TypeRelationEdge>> evilNodeEdges) {
        this.evilNodes.addAll(evilNodes);
        this.evilNodeEdges.putAll(evilNodeEdges);
    }
}
