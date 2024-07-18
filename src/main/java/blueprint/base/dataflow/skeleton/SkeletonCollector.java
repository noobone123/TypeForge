package blueprint.base.dataflow.skeleton;

import blueprint.base.dataflow.SymbolExpr.ParsedExpr;
import blueprint.base.dataflow.SymbolExpr.SymbolExpr;
import blueprint.base.dataflow.SymbolExpr.SymbolExprManager;
import blueprint.base.dataflow.UnionFind;
import blueprint.utils.Logging;

import java.util.*;

public class SkeletonCollector {
    private final Set<Skeleton> skeletons;
    /* Map[SymbolExpr, Set[Skeleton]]: this is temp data structure before handling skeletons */
    private final Map<SymbolExpr, Set<Skeleton>> exprToSkeletons_T;
    /* Map[SymbolExpr, Skeleton]: this is final data structure, very important */
    private final Map<SymbolExpr, Skeleton> exprToSkeletonMap;

    /* SymbolExprs that have multiple skeletons */
    private final Set<SymbolExpr> multiSkeletonExprs;

    private final SymbolExprManager exprManager;

    public SkeletonCollector(SymbolExprManager exprManager) {
        this.skeletons = new HashSet<>();
        this.exprToSkeletons_T = new HashMap<>();
        this.exprToSkeletonMap = new HashMap<>();
        this.multiSkeletonExprs = new HashSet<>();

        this.exprManager = exprManager;
    }

    /**
     * Merge and rebuild Skeletons, generate `exprToSkeletonMap`
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

    public void parseAndSetTypeAlias(SymbolExpr expr, UnionFind<SymbolExpr> aliasMap) {
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
                        Optional<Skeleton> mergedRes = null;
                        Skeleton newSkeleton = null;
                        if (skt1.hasMultiConstraints && skt2.hasMultiConstraints) {
                            Logging.warn("SkeletonCollector", "all have multi constraints");
                            mergedRes = Skeleton.mergeSkeletons(skt1, skt2, false);
                        } else if (skt1.hasMultiConstraints || skt2.hasMultiConstraints) {
                            Logging.warn("SkeletonCollector", "one has multi constraints");
                            mergedRes = Skeleton.mergeSkeletons(skt1, skt2, true);
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
}
