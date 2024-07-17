package blueprint.base.dataflow.skeleton;

import blueprint.base.dataflow.SymbolExpr.SymbolExpr;
import ghidra.program.model.data.DataType;

import java.util.HashSet;
import java.util.Set;

public class Skeleton {
    public final java.util.UUID uuid = java.util.UUID.randomUUID();
    public final String shortUUID = java.util.UUID.randomUUID().toString().substring(0, 8);

    public Set<TypeConstraint> constraints = new HashSet<>();
    public Set<SymbolExpr> exprs = new HashSet<>();
    public boolean hasMultiConstraints = false;

    public Set<DataType> derivedTypes;

    public Skeleton() { }

    public Skeleton(TypeConstraint constraints, Set<SymbolExpr> exprs) {
        this.constraints.add(constraints);
        this.exprs.addAll(exprs);
    }

    public Skeleton(Set<TypeConstraint> constraints, SymbolExpr expr) {
        this.constraints.addAll(constraints);
        this.exprs.add(expr);
    }

    public void addExpr(SymbolExpr expr) {
        exprs.add(expr);
    }

    public void mergeSkeletonFrom(Skeleton other) {
        this.constraints.addAll(other.constraints);
        this.exprs.addAll(other.exprs);
        this.hasMultiConstraints = this.hasMultiConstraints || other.hasMultiConstraints;
    }

    public int getConstraintsHash() {
        return constraints.hashCode();
    }

    @Override
    public int hashCode() {
        return uuid.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof Skeleton) {
            return this.uuid.equals(((Skeleton) obj).uuid);
        }
        return false;
    }

    @Override
    public String toString() {
        return "Skeleton_" + shortUUID;
    }
}
