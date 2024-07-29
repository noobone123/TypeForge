package blueprint.base.dataflow.skeleton;

import blueprint.base.dataflow.SymbolExpr.ParsedExpr;
import blueprint.base.dataflow.SymbolExpr.SymbolExpr;
import blueprint.base.dataflow.SymbolExpr.SymbolExprManager;
import blueprint.base.dataflow.UnionFind;
import blueprint.base.dataflow.typeRelation.TypeRelationGraph;
import blueprint.base.dataflow.typeRelation.TypeRelationPath;
import blueprint.utils.Logging;

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
                Logging.info("SkeletonCollector", String.format("Skeleton with single Constraint has Exprs: \n%s", skt.exprs));
                Logging.info("SkeletonCollector", String.format("Constraint: \n%s", skt.constraints.iterator().next().dumpLayout(0)));
            } else {
                assert skt.constraints.size() > 1;
                Logging.info("SkeletonCollector", String.format("Skeleton with multiple Constraints has Exprs: \n%s", skt.exprs));
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

        /* Handle MultiLevel Ptr Reference */
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            for (var offset: skt.ptrReference.keySet()) {
                if (skt.ptrReference.get(offset).size() > 1) {
                    continue;
                }

                var ptrEESkt = skt.ptrReference.get(offset).iterator().next();
                var ptrLevel = 1;
                while (ptrEESkt.isMultiLevelPtr()) {
                    ptrLevel++;
                    ptrEESkt = ptrEESkt.ptrReference.get(0L).iterator().next();
                }

                if (ptrLevel > 1) {
                    Logging.info("SkeletonCollector", String.format("Ptr Level > 1,  = %d", ptrLevel));
                    skt.ptrLevel.put(offset, ptrLevel);
                    skt.ptrReference.put(offset, Set.of(ptrEESkt));

                    /* For debug */
                    Logging.info("SkeletonCollector", String.format("Ptr Reference at 0x%s -> %s", Long.toHexString(offset), ptrEESkt));
                    Logging.info("SkeletonCollector", skt.exprs.toString());
                    Logging.info("SkeletonCollector", skt.finalConstraint.dumpLayout(0));
                    Logging.info("SkeletonCollector", ptrEESkt.exprs.toString());
                    Logging.info("SkeletonCollector", ptrEESkt.finalConstraint.dumpLayout(0));
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

    /**
     * This method should be called after all skeletons are successfully handled.
     */
    public void handleDecompilerInferredTypes() {
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            for (var expr: skt.exprs) {
                if (expr.isVariable()) {
                    var inferredType = exprManager.getInferredType(expr);
                    inferredType.ifPresent(skt::updateDerivedTypes);
                }
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
                        aliasMap.union(e, expr);
                        Logging.info("SkeletonCollector", String.format("Type Alias Detected: %s <--> %s", e, expr));
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
