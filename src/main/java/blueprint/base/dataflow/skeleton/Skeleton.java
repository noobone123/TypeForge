package blueprint.base.dataflow.skeleton;

import blueprint.base.dataflow.SymbolExpr.SymbolExpr;
import blueprint.utils.DataTypeHelper;
import blueprint.utils.Global;
import blueprint.utils.Logging;
import ghidra.program.model.data.DataType;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.Map;

public class Skeleton {
    public final java.util.UUID uuid = java.util.UUID.randomUUID();
    public final String shortUUID = java.util.UUID.randomUUID().toString().substring(0, 8);

    public Set<TypeConstraint> constraints = new HashSet<>();
    public TypeConstraint finalConstraint;
    public Set<SymbolExpr> exprs = new HashSet<>();
    public Set<SymbolExpr> variables = new HashSet<>();
    public boolean hasMultiConstraints = false;

    public Map<Long, Set<Skeleton>> ptrReference = new HashMap<>();
    public Map<Long, Skeleton> finalPtrReference = new HashMap<>();
    public Map<Long, Integer> ptrLevel = new HashMap<>();
    public Map<Long, Set<Skeleton>> mayNestedSkeleton = new HashMap<>();

    public boolean isPointerToPrimitive = false;
    public Set<DataType> derivedTypes;
    public DataType finalType;

    public Skeleton() { }

    public Skeleton(TypeConstraint constraints, Set<SymbolExpr> exprs) {
        this.constraints.add(constraints);
        this.exprs.addAll(exprs);
    }

    public Skeleton(Set<TypeConstraint> constraints, SymbolExpr expr) {
        this.constraints.addAll(constraints);
        this.exprs.add(expr);
    }

    public Skeleton(Set<TypeConstraint> constraints, Set<SymbolExpr> exprs) {
        this.constraints.addAll(constraints);
        this.exprs.addAll(exprs);
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

    public void addPtrReference(long ptr, Skeleton skt) {
        ptrReference.computeIfAbsent(ptr, k -> new HashSet<>()).add(skt);
    }

    public boolean isMultiLevelPtr() {
        if (constraints.size() > 1) { return false; }
        var constraint = constraints.iterator().next();
        if (constraint.fieldAccess.size() != 1) { return false; }
        if (constraint.fieldAccess.get(0L) == null) { return false; }
        for (var element: constraint.fieldAccess.get(0L)) {
            var dataType = element.dataType;
            var size = dataType.getLength();
            if (size != Global.currentProgram.getDefaultPointerSize()) { return false; }
        }
        if (ptrReference.get(0L) == null) { return false; }
        return true;
    }

    public Set<SymbolExpr> getVariables() {
        if (!variables.isEmpty()) {
            return variables;
        }

        for (var expr: exprs) {
            if (expr.isVariable()) {
                variables.add(expr);
            }
        }
        return variables;
    }

    public void updateDerivedTypes(DataType dt) {
        if (derivedTypes == null) {
            derivedTypes = new HashSet<>();
        }
        derivedTypes.add(dt);
    }

    /**
     * If current skeleton has no pointer reference or nested skeletons, it is independent
     * @return true if independent
     */
    public boolean isIndependent() {
        return ptrReference.isEmpty() && mayNestedSkeleton.isEmpty();
    }

    /**
     * If current skeleton has a pointer reference to multiple skeletons, it has multi pointer reference
     */
    public boolean hasMultiPtrReferenceTo() {
        for (var entry: ptrReference.entrySet()) {
            if (entry.getValue().size() > 1) {
                return true;
            }
        }
        return false;
    }

    public boolean hasMultiNestedSkeleton() {
        for (var entry: mayNestedSkeleton.entrySet()) {
            if (entry.getValue().size() > 1) {
                return true;
            }
        }
        return false;
    }

    public boolean hasNestedSkeleton() {
        return !mayNestedSkeleton.isEmpty();
    }

    public boolean hasOneField() {
        return finalConstraint.fieldAccess.size() == 1;
    }

    public boolean decompilerInferredTypesHasComposite() {
        if (derivedTypes == null) {
            return false;
        }
        for (var dt: derivedTypes) {
            if (DataTypeHelper.isPointerToCompositeDataType(dt) || DataTypeHelper.isCompositeOrArray(dt)) {
                return true;
            }
        }
        return false;
    }

    public void setPrimitiveType(DataType dt) {
        isPointerToPrimitive = true;
        finalType = dt;
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

    public void dumpInfo() {
        Logging.info("Skeleton", " ------------------------------- Start --------------------------------- ");
        Logging.info("Skeleton", this.toString());
        if (hasMultiConstraints) {
            Logging.info("Skeleton", String.format("C > 1, = %d", constraints.size()));
        } else {
            Logging.info("Skeleton", "C = 1");
        }
        Logging.info("Skeleton", "Associated Exprs Count: " + exprs.size());
        Logging.info("Skeleton", "All Exprs: " + exprs);
        Logging.info("Skeleton", "Associated Variables Count: " + getVariables().size());
        Logging.info("Skeleton", "All Variables: " + getVariables());
        Logging.info("Skeleton", "Constraint:\n " + finalConstraint);
        Logging.info("Skeleton", finalConstraint.dumpLayout(0));
        Logging.info("Skeleton", "All Decompiler Inferred Types:\n" + derivedTypes);

        Logging.info("Skeleton", " ------------------------------- End --------------------------------- ");
    }

    /**
     * Merge two skeletons into a new skeleton
     * @param skt1 merged skeleton
     * @param skt2 merged skeleton
     * @param isStrongMerge if true, merge all constraints in set into one constraint; otherwise just merge constraints set
     * @return new merged skeleton
     */
    public static Optional<Skeleton> mergeSkeletons(Skeleton skt1, Skeleton skt2, boolean isStrongMerge) {
        var newConstraints = new HashSet<TypeConstraint>();
        var newExprs = new HashSet<SymbolExpr>();
        newConstraints.addAll(skt1.constraints);
        newConstraints.addAll(skt2.constraints);
        newExprs.addAll(skt1.exprs);
        newExprs.addAll(skt2.exprs);

        if (isStrongMerge) {
            var mergedConstraint = new TypeConstraint();
            var noConflict = true;
            for (var c: newConstraints) {
                noConflict = mergedConstraint.tryMerge(c);
                if (!noConflict) {
                    break;
                }
            }

            if (!noConflict) {
                Logging.warn("Skeleton", String.format("Failed to merge skeletons %s and %s", skt1, skt2));
                return Optional.empty();
            }

            Logging.info("Skeleton", String.format("Merged skeletons %s and %s", skt1, skt2));
            Logging.info("Skeleton", String.format("Merged constraints:\n %s", mergedConstraint.dumpLayout(0)));
            newConstraints.clear();
            newConstraints.add(mergedConstraint);
            var newSkeleton = new Skeleton(newConstraints, newExprs);
            newSkeleton.hasMultiConstraints = false;
            return Optional.of(newSkeleton);
        } else {
            var newSkeleton = new Skeleton(newConstraints, newExprs);
            newSkeleton.hasMultiConstraints = true;
            return Optional.of(newSkeleton);
        }
    }

}
