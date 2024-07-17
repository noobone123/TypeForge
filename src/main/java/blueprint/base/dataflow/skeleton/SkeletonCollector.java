package blueprint.base.dataflow.skeleton;

import blueprint.base.dataflow.SymbolExpr.SymbolExpr;
import blueprint.utils.Logging;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class SkeletonCollector {
    private final Set<Skeleton> skeletons;
    /* Map[SymbolExpr, Set[Skeleton]]: this is temp data structure before handling skeletons */
    private final Map<SymbolExpr, Set<Skeleton>> exprToSkeletons_T;
    /* Map[SymbolExpr, Skeleton]: this is final data structure, very important */
    private final Map<SymbolExpr, Skeleton> exprToSkeletonMap;

    /* SymbolExprs that have multiple skeletons */
    private final Set<SymbolExpr> multiSkeletonExprs;

    public SkeletonCollector() {
        this.skeletons = new HashSet<>();
        this.exprToSkeletons_T = new HashMap<>();
        this.exprToSkeletonMap = new HashMap<>();
        this.multiSkeletonExprs = new HashSet<>();
    }


    public void test() {
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
        Set<Skeleton> visited = new HashSet<>();
        for (var entry: exprToSkeletonMap.entrySet()) {
            var expr = entry.getKey();
            var skt = entry.getValue();
            if (!skt.exprs.contains(expr)) {
                Logging.error("SkeletonCollector", String.format("exprToSkeletonMap is inconsistent: %s -> %s", expr, skt));
            }

            if (!skt.hasMultiConstraints) continue;
            if (visited.contains(skt)) continue;
            visited.add(skt);
            Logging.info("SkeletonCollector", String.format("Skeleton with multiple Constraints has Exprs: %s", skt.exprs));
        }

        // Handle Memory Alias
        // Save ReferenceTo Information between Skeletons
    }


    public void addSkeleton(Skeleton skt) {
        skeletons.add(skt);
    }
}
