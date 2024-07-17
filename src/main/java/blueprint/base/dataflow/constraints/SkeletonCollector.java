package blueprint.base.dataflow.constraints;

import blueprint.base.dataflow.SymbolExpr.SymbolExpr;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class SkeletonCollector {
    private final Map<TypeConstraint, Set<SymbolExpr>> skeletonToExprs;
    private final Set<SymbolExpr> multiSkeletonExprs;

    public SkeletonCollector() {
        this.skeletonToExprs = new HashMap<>();
        this.multiSkeletonExprs = new HashSet<>();
    }


    public void updateSkeletonToExprs(TypeConstraint skeleton, SymbolExpr expr) {
        if (skeletonToExprs.containsKey(skeleton)) {
            skeletonToExprs.get(skeleton).add(expr);
        } else {
            Set<SymbolExpr> exprs = new HashSet<>();
            exprs.add(expr);
            skeletonToExprs.put(skeleton, exprs);
        }
    }
}
