package typeforge.base.dataflow.solver;

import typeforge.base.dataflow.TFG.TFGManager;
import typeforge.base.dataflow.constraint.Skeleton;
import typeforge.base.dataflow.constraint.TypeConstraint;
import typeforge.base.dataflow.expression.ParsedExpr;
import typeforge.base.dataflow.expression.NMAE;
import typeforge.base.dataflow.expression.NMAEManager;
import typeforge.base.dataflow.UnionFind;
import typeforge.utils.Global;
import typeforge.utils.Logging;
import typeforge.utils.TCHelper;

import java.util.*;

public class TypeHintCollector {

    private InterSolver interSolver;
    private NMAEManager exprManager;
    private TFGManager graphManager;

    /* Map[SymbolExpr, Skeleton]: this is final data structure, very important */
    public final Map<NMAE, TypeConstraint> exprToConstraintMap;
    private final Set<TypeConstraint> typeConstraints;

    public TypeHintCollector(InterSolver interSolver) {
        this.typeConstraints = new HashSet<>();
        this.exprToConstraintMap = new HashMap<>();

        this.interSolver = interSolver;
        this.exprManager = this.interSolver.exprManager;
        this.graphManager = this.interSolver.graphManager;
    }

    public void run() {
        // Since EvilEdges has been removed during aforementioned const propagation and layout propagation,
        // Now we need to aggregate the type hints from connected components in the whole-program TFG.
        buildTypeConstraintsBySkeletons();
        handleTypeAlias();
        return;
    }

    public void buildTypeConstraintsBySkeletons() {
        var emptyCount = 0;
        var totalSingleMemberCount = 1;
        var totalCompositeCount = 0;

        for (var graph: graphManager.getGraphs()) {
            Skeleton finalSkeleton = null;
            if (!graph.isValid()) {
                Logging.error("TypeHintCollector", String.format("Unexpected Invalid Graph %s, skip it.", graph));
                continue;
            }

            if (graph.getNumNodes() < 1) {
                continue;
            } else if (graph.getNumNodes() == 1) {
                finalSkeleton = exprManager.getOrCreateSkeleton(graph.getNodes().iterator().next());
            } else {
                var success = graphManager.tryToMergeAllNodesSkeleton(graph, graph.getNodes(), exprManager);
                if (!success) {
                    Logging.error("TypeHintCollector", "This should not have happened, please check the Propagator.");
                    continue;
                }
                finalSkeleton = graph.finalSkeleton;
            }

            if (finalSkeleton.isEmpty()) {
                emptyCount += 1;
                continue;
            }

            var constraint = new TypeConstraint(finalSkeleton, graph.getNodes(), true);
            typeConstraints.add(constraint);
            for (var expr: graph.getNodes()) {
                exprToConstraintMap.put(expr, constraint);
            }

            if (constraint.hasOneField()) {
                totalSingleMemberCount += 1;
            }

            totalCompositeCount += 1;
        }

        Logging.debug("TypeHintCollector", String.format("Total Composite TypeConstraint: %d", totalCompositeCount));
        Logging.debug("TypeHintCollector", String.format("Total Empty TypeConstraint: %d", emptyCount));
        Logging.debug("TypeHintCollector", String.format("Total Single Member TypeConstraint: %d", totalSingleMemberCount));
    }

    /**
     * Similar to `handleMemoryAlias`,
     * if `*(a+0x8)` and `*(b+0x8)` has different TypeConstraint but `a` and `b` has same TypeConstraint.
     * We Consider `*(a+0x8)` and `*(b+0x8)` has same TypeConstraint and merge them.
     */
    public void handleTypeAlias() {
        /* initialize shareSameType using Skeleton's expressions */
        var shareSameType = new UnionFind<NMAE>();
        for (var constraint: new HashSet<>(exprToConstraintMap.values())) {
            // In theory, nodes from the same TFG should be connected in the same cluster in UnionFind.
            shareSameType.initializeWithCluster(constraint.exprs);
        }

        for (var expr: exprToConstraintMap.keySet()) {
            if (expr.isDereference()) {
                parseAndSetTypeAlias(expr, shareSameType);
            }
        }
    }

    private void parseAndSetTypeAlias(NMAE query, UnionFind<NMAE> shareSameType) {
        // IMPORTANT: this algorithm is not perfect, it didn't run until a fixed point is reached.
        // So UnionFind may cause some inconsistency problem.
        var parsed = ParsedExpr.parseFieldAccessExpr(query);
        if (parsed.isEmpty()) { return; }
        var parsedExpr = parsed.get();
        var base = parsedExpr.base;
        var offset = parsedExpr.offsetValue;
        if (base == null) { return; }

        if (parsedExpr.base.isDereference()) {
            parseAndSetTypeAlias(parsedExpr.base, shareSameType);
        }

        if (!shareSameType.contains(base)) {
            return;
        }

        // IMPORTANT: be careful, now new built shareSameType can not ensure that
        // all alias expr has no conflict, so we need to check it.
        // For example: if we are finding alias of *(a + 0x4),
        //  shareSameType.getCluster(base) can get all exprs that share the same type with `a` (like b, c),
        //  then we further use `exprManager.getFieldExprsByOffset(alias, offset)` to find *(b + 0x4) and *(c + 0x4) ...
        //  If these expr exists, they can be considered as alias of *(a + 0x4).
        for (var node: shareSameType.getCluster(base)) {
            var res = exprManager.getFieldExprsByOffset(node, offset);
            if (res.isEmpty()) { continue; }
            var queryAliases = res.get();
            for (var alias: queryAliases) {
                // Mark sure alias and query are all in union find
                if (shareSameType.contains(alias) && shareSameType.contains(query)) {
                    // If already in the same cluster, skip it.
                    if (shareSameType.connected(alias, query)) continue;

                    var aliasConstraint = exprToConstraintMap.get(alias);
                    var queryConstraint = exprToConstraintMap.get(query);

                    if (aliasConstraint.equals(queryConstraint)) continue;

                    // TODO: also checking polyTypes.
                    if (TypeConstraint.checkConstraintConflict(aliasConstraint, queryConstraint, true)) {
                        Logging.debug("TypeHintCollector", String.format("Detected Conflict Type Alias: %s <--> %s", alias, query));
                        continue;
                    }

                    Logging.debug("TypeHintCollector", String.format("Detect Regular Type Alias: %s <--> %s", alias, query));
                    shareSameType.union(alias, query);

                    Optional<TypeConstraint> mergedRes;

                    mergedRes = TypeConstraint.mergeConstraints(aliasConstraint, queryConstraint, true, true);

                    if (mergedRes.isPresent()) {
                        var mergedTypeConstraint = mergedRes.get();
                        /* update exprToSkeletonMap */
                        for (var e: mergedTypeConstraint.exprs) {
                            exprToConstraintMap.put(e, mergedTypeConstraint);
                        }
                        typeConstraints.remove(aliasConstraint);
                        typeConstraints.remove(queryConstraint);
                        typeConstraints.add(mergedTypeConstraint);
                    } else {
                        Logging.warn("TypeHintCollector", String.format("Failed to merge alias constraint of %s and %s", alias, query));
                    }
                }
            }
        }
    }

    /**
     * For Skeletons with multiple constraints, we choose the most visited one as the final constraint.
     */
    public void handleFinalConstraint() {
        for (var skt: new HashSet<>(exprToConstraintMap.values())) {
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
        for (var expr: exprToConstraintMap.keySet()) {
            if (!expr.isDereference()) {
                continue;
            }

            var parsed = ParsedExpr.parseFieldAccessExpr(expr);
            if (parsed.isEmpty()) continue;
            var parsedExpr = parsed.get();
            var base = parsedExpr.base;
            var offset = parsedExpr.offsetValue;

            if (exprToConstraintMap.containsKey(base)) {
                var baseSkt = exprToConstraintMap.get(base);
                baseSkt.addPtrReference(offset, exprToConstraintMap.get(expr));
                baseSkt.ptrLevel.put(offset, 1);
            }
        }

        /* In rare cases, for some reason, there may be some multi-ple ptr reference or nested skeletons */
        handleMultiPtrReferenceTo();

        /* Handle MultiLevel Ptr Reference */
        for (var skt: new HashSet<>(exprToConstraintMap.values())) {
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
        for (var skt: new HashSet<>(exprToConstraintMap.values())) {
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
        for (var skt: new HashSet<>(exprToConstraintMap.values())) {
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
     * Handle May Nesting Relationships between Skeletons
     * @param exprsAsArgument SymbolExpr that used as arguments in callSite.
     */
    public void handleNesting(Set<NMAE> exprsAsArgument) {
        /* Add MayNestedSkeleton */
        for (var expr: exprsAsArgument) {
            if (!exprToConstraintMap.containsKey(expr)) continue;
            /* If expr is a SymbolExpr like `base + offset`, we seem it as a may nested expr */
            if (expr.hasBase() && expr.hasOffset() && expr.getOffset().isNoZeroConst()) {
                var base = expr.getBase();
                var offset = expr.getOffset().getConstant();
                if (exprToConstraintMap.containsKey(base)) {
                    var baseSkt = exprToConstraintMap.get(base);
                    baseSkt.mayNestedConstraint.computeIfAbsent(offset, k -> new HashSet<>())
                            .add(exprToConstraintMap.get(expr));
                }
            }
        }

        /* Remove skeletons that should not be nested */
        for (var skt: new HashSet<>(exprToConstraintMap.values())) {
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
        for (var skt: new HashSet<>(exprToConstraintMap.values())) {
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
        for (var skt: new HashSet<>(exprToConstraintMap.values())) {
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
        for (var skt: new HashSet<>(exprToConstraintMap.values())) {
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
        for (var skt: new HashSet<>(exprToConstraintMap.values())) {
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
        for (var skt: new HashSet<>(exprToConstraintMap.values())) {
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
}
