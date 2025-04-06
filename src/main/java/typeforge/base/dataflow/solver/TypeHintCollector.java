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

import java.util.*;

public class TypeHintCollector {

    private InterSolver interSolver;
    private NMAEManager exprManager;
    private TFGManager graphManager;

    /* Map[SymbolExpr, Skeleton]: this is final data structure, very important */
    public final Map<NMAE, TypeConstraint> exprToConstraintMap;

    public TypeHintCollector(InterSolver interSolver) {
        this.exprToConstraintMap = new HashMap<>();

        this.interSolver = interSolver;
        this.exprManager = this.interSolver.exprManager;
        this.graphManager = this.interSolver.graphManager;
    }

    public void run() {
        // Since EvilEdges has been removed during aforementioned const propagation and layout propagation,
        // Now we need to aggregate the type hints from connected components in the whole-program TFG.
        // IMPORTANT: Following handlers' order should not be changed.
        buildTypeConstraintsBySkeletons();
        confirmFinalConstraint();
        handleMayPrimitiveConstraints();
        handleTypeAlias();

        preHandlePtrReference();
        handleNesting(exprManager.getExprsByAttribute(NMAE.Attribute.ARGUMENT));
        postHandlePtrReference();
        handleMemberConflict();
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

            var constraint = new TypeConstraint(finalSkeleton, graph.getNodes());
            for (var expr: constraint.exprs) {
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

        // The purpose of handling type alias is to merge composite type layouts.
        // We need to note that if a member access expression is of composite types, it means it is a pointer reference to another composite type,
        // For example, the composite type corresponding to `*(a+0x8)` is the pointer reference at the 0x8 offset of `a`.
        // It is worth mentioning that the offset of such pointer references is aligned with the default pointer size.
        // Therefore, for other fields such as `*(a+0x1)`, they are primitive types and do not require Alias calculation.
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
        // IMPORTANT ...
        if (Global.currentProgram.getDefaultPointerSize() > 0) {
            if (offset % Global.currentProgram.getDefaultPointerSize() != 0) {
                return;
            }
        }
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
                    var aliasConstraint = exprToConstraintMap.get(alias);
                    var queryConstraint = exprToConstraintMap.get(query);

                    // If alias or query is a pointer to primitive type, we do not merged them.
                    if (aliasConstraint.mayPointerToPrimitive || queryConstraint.mayPointerToPrimitive) {
                        Logging.debug("TypeHintCollector", String.format("Detected Pointer to Primitive Type Alias: %s <--> %s", alias, query));
                        continue;
                    }
                    // If already in the same cluster, skip it.
                    if (aliasConstraint.equals(queryConstraint)) continue;

                    var result = TypeConstraint.mergeConstraint(aliasConstraint, queryConstraint, false);
                    if (result.isEmpty()) {
                        Logging.debug("TypeHintCollector", String.format("Detected Conflict Type Alias: %s <--> %s", alias, query));
                    } else {
                        Logging.debug("TypeHintCollector", String.format("Detect Regular Type Alias: %s <--> %s", alias, query));
                        shareSameType.union(alias, query);
                        var mergedConstraint = result.get();
                        for (var e: mergedConstraint.exprs) {
                            exprToConstraintMap.put(e, mergedConstraint);
                        }
                    }
                }
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

                if (Global.currentProgram.getDefaultPointerSize() > 0
                        && offset % Global.currentProgram.getDefaultPointerSize() != 0) {
                    Logging.debug("TypeHintCollector",
                            String.format("Offset 0x%x is not aligned (Nested) with pointer size, skip it.", offset));
                    continue;
                }

                if (exprToConstraintMap.containsKey(base)) {
                    Logging.debug("TypeHintCollector",
                            String.format("Offset 0x%x is aligned (Nested) with pointer size.", offset));
                    var nester = exprToConstraintMap.get(base);
                    var nestee = exprToConstraintMap.get(expr);
                    if (nestee.mayPointerToPrimitive) {
                        Logging.debug("TypeHintCollector", String.format("Nestee may be a pointer to primitive type: %s", nestee));
                        continue;
                    }
                    if (nester == nestee) {
                        Logging.debug("TypeHintCollector", String.format("Nester and Nestee are the same: %s", nester));
                        continue;
                    }
                    if (TypeConstraint.checkNestConflict(nester, nestee, offset, false)) {
                        nester.nestedConstraint.computeIfAbsent(offset, k -> new HashSet<>())
                                .add(nestee);
                        Logging.debug("TypeHintCollector", String.format("No conflicts when nest %s and %s", nester, nestee));
                    } else {
                        Logging.debug("TypeHintCollector", String.format("Can not nest %s and %s", nester, nestee));
                    }
                }
            }
        }

        /* Handling mayNested Skeleton and build the finalNestedSkeleton */
        for (var nester: new HashSet<>(exprToConstraintMap.values())) {
            for (var entry: nester.nestedConstraint.entrySet()) {
                var offset = entry.getKey();
                var nestedConstraints = entry.getValue();
                if (nestedConstraints.size() == 1) {
                    Logging.debug("TypeHintCollector", String.format("Single Nested Constraints Detected: %s", nestedConstraints));
                    nester.finalNestedConstraint.put(entry.getKey(), nestedConstraints.iterator().next());
                }
                else if (nestedConstraints.size() > 1) {
                    Logging.debug("TypeHintCollector", String.format("Multiple Nested Constraints Detected: %s", nestedConstraints));
                    // If multiple nested constraints detected,
                    // we choose the constraints associated with the most number of variables and use it as the final constraint.
                    TypeConstraint choose = null;
                    for (var nestee: nestedConstraints) {
                        if (choose == null) {
                            choose = nestee;
                        } else {
                            if (nestee.getVariables().size() >= choose.getVariables().size()) {
                                choose = nestee;
                            }
                        }
                    }
                    nester.finalNestedConstraint.put(offset, choose);
                }

                var finalNestee = nester.finalNestedConstraint.get(offset);
                tryPopulateNester(nester, finalNestee, offset);
                nester.updateNestedRange(offset, offset + finalNestee.getMaxSize());
            }
        }
    }

    /**
     * For Skeletons with multiple constraints, we choose the most visited one as the final constraint.
     */
    public void confirmFinalConstraint() {
        for (var constraint: new HashSet<>(exprToConstraintMap.values())) {
            if (constraint.innerSkeleton == null) {
                Logging.error("TypeHintCollector", "Inner Skeleton is null, please check the code.");
            }
        }
    }

    /**
     * Parsing the dereference expression and build the basic pointer reference relationship.
     * There may multiple pointer references to the same offset, we will process them later.
     */
    public void preHandlePtrReference() {
        for (var expr: exprToConstraintMap.keySet()) {
            if (!expr.isDereference()) {
                continue;
            }

            var parsed = ParsedExpr.parseFieldAccessExpr(expr);
            if (parsed.isEmpty()) continue;
            var parsedExpr = parsed.get();
            var base = parsedExpr.base;
            var offset = parsedExpr.offsetValue;
            // IMPORTANT: offset should be aligned with pointer size
            if (Global.currentProgram.getDefaultPointerSize() > 0) {
                if (offset % Global.currentProgram.getDefaultPointerSize() != 0) {
                    Logging.debug("TypeHintCollector", String.format("Offset 0x%x is not aligned with pointer size, skip it.", offset));
                    continue;
                }
            }

            if (exprToConstraintMap.containsKey(base)) {
                Logging.debug("TypeHintCollector", String.format("Offset 0x%x is aligned with pointer size.", offset));
                var baseConstraint = exprToConstraintMap.get(base);

                baseConstraint.ptrReference
                        .computeIfAbsent(offset, k -> new HashSet<>()).add(exprToConstraintMap.get(expr));
                baseConstraint.ptrLevel.put(offset, 1);
            }
        }
    }

    /**
     * Post handle the pointer reference relationship.
     * Including:
     *  1. Handle multi pointer reference to the same offset
     *  2. Handle multi-level pointer reference
     */
    public void postHandlePtrReference() {
        /* There may multiple ptr reference to the same offset, we need to handle it */
        handleMultiPtrReferenceTo();

        /* Handle Multi-Level Ptr Reference */
        for (var constraint: new HashSet<>(exprToConstraintMap.values())) {
            for (var offset: constraint.finalPtrReference.keySet()) {
                var ptrEEConstraint = constraint.finalPtrReference.get(offset);
                var ptrLevel = 1;
                while (ptrEEConstraint.checkMultiLevelMidPtr()) {
                    ptrLevel++;
                    if (ptrEEConstraint == ptrEEConstraint.finalPtrReference.get(0L)) {
                        Logging.warn("TypeHintCollector", "Ptr Reference Loop Detected!");
                        break;
                    }
                    ptrEEConstraint = ptrEEConstraint.finalPtrReference.get(0L);
                }

                if (ptrLevel > 1) {
                    Logging.debug("TypeHintCollector", String.format("Ptr Level > 1,  = %d", ptrLevel));
                    constraint.ptrLevel.put(offset, ptrLevel);
                    constraint.finalPtrReference.put(offset, ptrEEConstraint);
                } else {
                    Logging.debug("TypeHintCollector", "Ptr Level = 1");
                }
            }
        }
    }

    /**
     * In Type Skeleton, some member may have conflict point to reference, we need to handle it.
     */
    public void handleMemberConflict() {
        var ptrSize = Global.currentProgram.getDefaultPointerSize();
        for (var constraint: new HashSet<>(exprToConstraintMap.values())) {
            List<Long> offsets = new ArrayList<>(constraint.innerSkeleton.fieldAccess.keySet());
            Collections.sort(offsets);
            List<Long> removedFields = new ArrayList<>();

            for (int i = 0; i < offsets.size(); i++) {
                var offset = offsets.get(i);
                var aps = constraint.innerSkeleton.fieldAccess.get(offset);

                if (i == offsets.size() - 1) break;
                var nextOffset = offsets.get(i + 1);

                // If there is a pointer reference at this offset, but the size between this offset and the next offset is less than the pointer size,
                // we consider it as a conflict and remove the pointer reference.
                if (constraint.finalPtrReference.containsKey(offset)) {
                    if ((nextOffset - offset) < ptrSize) {
                        constraint.finalPtrReference.remove(offset);
                        Logging.debug("TypeHintCollector", String.format("Found Conflict Member's Ptr Reference at 0x%s", Long.toHexString(offset)));
                    }
                }

                // Use mostAccessedDT to check if the size between this offset and the next offset is
                // less than the size of the most accessed data type.
                var size = aps.mostAccessedDT.getLength();
                if ((nextOffset - offset) < size) {
                    removedFields.add(offset);
                    Logging.debug("TypeHintCollector", String.format("Found Conflict Member at 0x%s", Long.toHexString(offset)));
                    Logging.debug("TypeHintCollector", String.format("MostAccessedDTSize = %d", size));
                    Logging.debug("TypeHintCollector", String.format("Next Offset = 0x%s", Long.toHexString(nextOffset)));
                }
            }

            for (var offset: removedFields) {
                constraint.innerSkeleton.fieldAccess.remove(offset);
            }
        }
    }

    public void handleMultiPtrReferenceTo() {
        /* Choose the most visited one as the final ReferenceTo constraint */
        for (var constraint: new HashSet<>(exprToConstraintMap.values())) {
            for (var offset: constraint.ptrReference.keySet()) {
                var ptrEEs = constraint.ptrReference.get(offset);
                if (ptrEEs.size() == 1) {
                    var ptrEE = ptrEEs.iterator().next();
                    constraint.finalPtrReference.put(offset, ptrEE);
                } else {
                    Logging.warn("TypeHintCollector", String.format("Multi Ptr Reference To Detected: \n%s", constraint));
                    // TODO: Try to merge them into a new constraint?
                    TypeConstraint choose = null;
                    for (var ptrEE: ptrEEs) {
                        if (choose == null) {
                            choose = ptrEE;
                        } else {
                            if (ptrEE.getVariables().size() > choose.getVariables().size()) {
                                choose = ptrEE;
                            }
                        }
                    }
                    constraint.finalPtrReference.put(offset, choose);
                }
            }
        }
    }

    /**
     * Some Type Constraint may correspond to a pointer to primitive type or primitive array.
     * We should find and mark them.
     */
    public void handleMayPrimitiveConstraints() {
        for (var c: exprToConstraintMap.values()) {
            if (c.hasOneFirstField() && !c.hasDecompilerInferredCompositeType()) {
                Logging.debug("TypeHintCollector", "Maybe Pointer to Primitive Detected: " + c);
                c.dumpInfo();
                c.mayPointerToPrimitive = true;
                return;
            }

            // If there are multiple stack allocated arrays and variables in the constraint,
            // still consider its may be a pointer to primitive type.
            if (c.hasDecompilerInferredCompositeType()) {
                var inferredTypes = c.decompilerInferredCompositeTypes;
                if (inferredTypes.size() >= 2) {
                    if (c.onlyArraysInDecompilerInferredCompositeTypes()) {
                        Logging.debug("TypeHintCollector", "Maybe Pointer to Primitive Array (due to arrays) Detected: " + c);
                        c.dumpInfo();
                        c.mayPointerToPrimitive = true;
                        return;
                    }
                }
            }

            // If there are multiple same size members in the constraint
            if (c.hasMultipleNonPointerSameSizeMembers()) {
                Logging.debug("TypeHintCollector", "Maybe Pointer to Primitive Array (due to duplicates) Detected: " + c);
                c.dumpInfo();
                c.mayPointerToPrimitive = true;
            }
        }
    }

    /**
     * Try to populate the nester's skeleton with the nestee's skeleton.
     * It's worthy to note that finalPtrReference has not been decided yet.
     */
    private void tryPopulateNester(TypeConstraint nester, TypeConstraint nestee,
                                   long nestedOffset) {
        var nesterSkeleton = nester.innerSkeleton;
        var nesteeSkeleton = nestee.innerSkeleton;
        var nested = new Skeleton(nesteeSkeleton, nestedOffset);
        var canMerge = nesterSkeleton.tryMergeLayoutStrict(nested);
        if (!canMerge) {
            Logging.debug("TypeHintCollector",
                    "This nested error should not have happened, please check the code.");
            return;
        }
        nester.handleFieldAPSet();
        nester.setMaxSize();

        for (var offset: nestee.ptrReference.keySet()) {
            var nesteePtrRef = nestee.ptrReference.get(offset);
            var nesterOffset = nestedOffset + offset;
            nester.ptrReference.computeIfAbsent(nesterOffset, k -> new HashSet<>()).addAll(nesteePtrRef);
        }
    }
}
