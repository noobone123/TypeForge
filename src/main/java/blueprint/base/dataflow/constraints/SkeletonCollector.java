package blueprint.base.dataflow.constraints;

import blueprint.base.dataflow.SymbolExpr.SymbolExpr;
import blueprint.utils.Logging;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class SkeletonCollector {
    /* Many Expr only holds one skeleton */
    private final Map<TypeConstraint, Set<SymbolExpr>> singleSkeletonToExprs;
    /* Some Expr holds multiple skeletons */
    private final Map<Set<TypeConstraint>, Set<SymbolExpr>> multiSkeletonToExprs;
    private final Map<SymbolExpr, Set<TypeConstraint>> exprToSkeletons;

    /* SymbolExprs that have multiple skeletons */
    private final Set<SymbolExpr> multiSkeletonExprs;

    public SkeletonCollector() {
        this.singleSkeletonToExprs = new HashMap<>();
        this.multiSkeletonToExprs = new HashMap<>();
        this.exprToSkeletons = new HashMap<>();
        this.multiSkeletonExprs = new HashSet<>();
    }


    public void test() {
        // Generate expr To Skeletons
        for (var entry: singleSkeletonToExprs.entrySet()) {
            var skeleton = entry.getKey();
            var exprs = entry.getValue();
            for (var expr: exprs) {
                exprToSkeletons.computeIfAbsent(expr, k -> new HashSet<>()).add(skeleton);
            }
        }

        // Find and mark SymbolExprs that have multiple skeletons
        for (var entry: exprToSkeletons.entrySet()) {
            var expr = entry.getKey();
            var skeletons = entry.getValue();
            if (skeletons.size() == 1) {
                Logging.info("SkeletonCollector", String.format("%s: S = 1", expr));
            }
            else if (skeletons.size() > 1) {
                multiSkeletonExprs.add(expr);
                Logging.info("SkeletonCollector", String.format("%s: S > 1", expr));
                for (var skeleton: skeletons) {
                    Logging.info("SkeletonCollector", String.format("Layout:\n%s", skeleton.dumpLayout(0)));
                }
            }
        }

        // Remove multiSkeletonExprs from singleSkeletonToExprs
        for (var expr: multiSkeletonExprs) {
            for (var entry: singleSkeletonToExprs.entrySet()) {
                var exprs = entry.getValue();
                var removed = exprs.remove(expr);
                if (removed) {
                    Logging.info("SkeletonCollector", String.format("%s is removed from singleSkeletonToExprs: %s", expr, entry.getKey()));
                }
            }
        }

        // Build multiSkeletonToExprs
        for (var expr: multiSkeletonExprs) {
            var skeletons = exprToSkeletons.get(expr);
            multiSkeletonToExprs.computeIfAbsent(skeletons, k -> new HashSet<>()).add(expr);
        }

        // Dump multiSkeletonToExprs for debugging
        for (var entry: multiSkeletonToExprs.entrySet()) {
            var skeletons = entry.getKey();
            var exprs = entry.getValue();
            Logging.info("SkeletonCollector", String.format("These Exprs with Same MultiSkeleton:\n %s", exprs));
            for (var skeleton: skeletons) {
                Logging.info("SkeletonCollector", String.format("Skeleton:\n%s", skeleton.dumpLayout(0)));
            }
        }

        // Assert: there is no intersection between singleSkeletonToExprs and multiSkeletonToExprs

    }


    public void updateSkeletonToExprs(TypeConstraint skeleton, SymbolExpr expr) {
        if (singleSkeletonToExprs.containsKey(skeleton)) {
            singleSkeletonToExprs.get(skeleton).add(expr);
        } else {
            Set<SymbolExpr> exprs = new HashSet<>();
            exprs.add(expr);
            singleSkeletonToExprs.put(skeleton, exprs);
        }
    }
}
