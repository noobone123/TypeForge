package blueprint.base.dataflow.skeleton;

import blueprint.base.dataflow.AccessPoints;
import blueprint.base.dataflow.SymbolExpr.SymbolExpr;
import blueprint.utils.DataTypeHelper;
import blueprint.utils.Global;
import blueprint.utils.Logging;
import ghidra.program.model.data.DataType;
import jnr.ffi.annotations.In;

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
    public boolean mayPrimitiveArray = false;
    public boolean singleDerivedType = false;

    /* If there are multiple fields in the Constraint need to generate and assessment (We call it MorphingPoint) In order to reduce time complexity,
     *  we try to assess each MorphingPoint and choose the best one to generate the final structure. */
    public Map<Long, Set<DataType>> morphingPoints = new HashMap<>();
    public Set<DataType> derivedTypes;
    public DataType finalType;

    public int size = -1;

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
     * Get the size of current skeleton, we consider the
     * max of (finalConstraint.fieldAccess.size(), finalConstraint.fieldAccess.size() + nestedSkeleton.size())
     * @return the size of current skeleton
     */
    public int getSize() {
        if (size != -1) {
            return size;
        }

        /* Get the last element of fieldAccess */
        var maxSize = 0L;
        for (var entry: finalConstraint.fieldAccess.entrySet()) {
            var offset = entry.getKey();
            var maxSizeAtOffset = AccessPoints.getMaxSizeInAPSet(entry.getValue());
            if (offset + maxSizeAtOffset > maxSize) {
                maxSize = offset + maxSizeAtOffset;
            }
            /* Consider nested skeletons */
            if (mayNestedSkeleton.containsKey(offset)) {
                for (var skt: mayNestedSkeleton.get(offset)) {
                    var nestedSize = skt.getSize();
                    if (offset + nestedSize > maxSize) {
                        maxSize = offset + nestedSize;
                    }
                }
            }
        }

        size = (int) maxSize;
        return size;
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

    public boolean hasPtrReference() {
        return !ptrReference.isEmpty();
    }

    public boolean mayPrimitiveArray() {
        var fieldAccess = finalConstraint.fieldAccess;
        var windowSize = 0;
        var hitCount = 0;

        for (var entry: fieldAccess.entrySet()) {
            var offset = entry.getKey();
            var apSet = entry.getValue();
            if (!AccessPoints.ifAPSetHoldsSameSizeType(apSet)) {
                return false;
            }
            if (windowSize == 0) {
                /* we expect that windowSize starts from offset 0x0 */
                if (offset > 0) {
                    return false;
                }
                windowSize = apSet.iterator().next().dataType.getLength();
                // TODO: this is a assumption, maybe need to remove in abandoned study.
                if (windowSize >= Global.currentProgram.getDefaultPointerSize()) {
                    return false;
                }
            }
            if (windowSize != apSet.iterator().next().dataType.getLength()) {
                return false;
            } else {
                hitCount++;
            }
        }

        return hitCount >= 2;
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
        singleDerivedType = true;
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
        Logging.info("Skeleton", "Morphing Points: ");
        for (var entry: morphingPoints.entrySet()) {
            Logging.info("Skeleton", "Morphing Offset: 0x" + Long.toHexString(entry.getKey()));
            for (var dt: entry.getValue()) {
                Logging.info("Skeleton", dt.toString());
            }
        }

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
