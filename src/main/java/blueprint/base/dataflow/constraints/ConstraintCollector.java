package blueprint.base.dataflow.constraints;

import blueprint.base.dataflow.SymbolExpr.SymbolExpr;
import blueprint.utils.Logging;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

public class ConstraintCollector {
    private final Map<SymbolExpr, TypeConstraint> exprToConstraint;

    public ConstraintCollector() {
        this.exprToConstraint = new HashMap<>();
    }

    // TODO: getConstraint and createConstraint should split into two functions ?
    public TypeConstraint getConstraint(SymbolExpr expr) {
        TypeConstraint constraint;
        if (exprToConstraint.containsKey(expr)) {
            constraint = exprToConstraint.get(expr);
        } else {
            constraint = new TypeConstraint();
            exprToConstraint.put(expr, constraint);
            Logging.debug("ConstraintCollector", String.format("Create Constraint_%s for %s", constraint.shortUUID, expr));
        }
        constraint.addAssociatedExpr(expr);
        Logging.debug("ConstraintCollector", String.format("Get Constraint_%s for %s", constraint.shortUUID, expr));
        return constraint;
    }

    public void updateConstraint(SymbolExpr expr, TypeConstraint constraint) {
        exprToConstraint.put(expr, constraint);
        constraint.addAssociatedExpr(expr);
        Logging.debug("ConstraintCollector", String.format("Update Constraint_%s for %s", constraint.shortUUID, expr));
    }

    public Set<SymbolExpr> getAllExprs() {
        return new HashSet<>(exprToConstraint.keySet());
    }

    public Set<TypeConstraint> getAllConstraints() {
        return new HashSet<>(exprToConstraint.values());
    }

    public Map<SymbolExpr, TypeConstraint> getAllEntries() {
        return new HashMap<>(exprToConstraint);
    }

    public ConstraintCollector copy() {
        ConstraintCollector newCollector = new ConstraintCollector();
        newCollector.exprToConstraint.putAll(exprToConstraint);
        return newCollector;
    }

    public void updateAllEntries(Map<SymbolExpr, TypeConstraint> entries) {
        exprToConstraint.clear();
        exprToConstraint.putAll(entries);
    }

    public boolean hasConstraint(SymbolExpr expr) {
        return exprToConstraint.containsKey(expr);
    }
}
