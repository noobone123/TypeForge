package typeclay.base.dataflow.skeleton;

import typeclay.base.dataflow.Range;
import typeclay.base.dataflow.SymbolExpr.SymbolExpr;
import typeclay.utils.DataTypeHelper;
import typeclay.utils.Global;
import typeclay.utils.Logging;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;

import java.util.*;
import java.util.stream.Stream;

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
    public Map<Long, Skeleton> finalNestedSkeleton = new HashMap<>();

    public Set<Long> inConsistentOffsets = new HashSet<>();

    public boolean isPointerToPrimitive = false;
    public boolean isMultiLevelMidPtr = false;
    public boolean mayPrimitiveArray = false;
    public boolean singleDerivedType = false;

    /**
     *  If there are multiple fields in the Constraint need to generate and assessment (We call it MorphingPoint)
     *  In order to reduce time complexity, we try to assess each morphRange and choose the best one in each morphRange.
     *  And finally, we will synthesize the final result based on every best choice in each morphRange.
     */
    public Set<DataType> globalMorphingTypes = new HashSet<>();
    public Map<Range, Set<DataType>> rangeMorphingTypes = new HashMap<>();
    public Map<Range, Set<Integer>> rangeMorphingTypeHash = new HashMap<>();
    public Set<Range> nestedRange = new HashSet<>();
    public Set<DataType> decompilerInferredTypes;
    public DataType finalType = null;

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

    public boolean isMultiLevelMidPtr() {
        if (constraints.size() > 1) { return false; }
        var constraint = constraints.iterator().next();
        if (constraint.fieldAccess.size() != 1) { return false; }
        if (constraint.fieldAccess.get(0L) == null) { return false; }
        for (var element: constraint.fieldAccess.get(0L).getApSet()) {
            var dataType = element.dataType;
            var size = dataType.getLength();
            if (size != Global.currentProgram.getDefaultPointerSize()) { return false; }
        }
        if (finalPtrReference.get(0L) == null) { return false; }
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
            var maxSizeAtOffset = entry.getValue().maxDTSize;
            if (offset + maxSizeAtOffset > maxSize) {
                maxSize = offset + maxSizeAtOffset;
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
        return !finalPtrReference.isEmpty();
    }

    public boolean mayPrimitiveArray() {
        var fieldAccess = finalConstraint.fieldAccess;
        var windowSize = 0;
        var hitCount = 0;

        for (var entry: fieldAccess.entrySet()) {
            var offset = entry.getKey();
            var apSet = entry.getValue();
            if (!apSet.isSameSizeType) {
                return false;
            }
            if (windowSize == 0) {
                /* we expect that windowSize starts from offset 0x0 */
                if (offset > 0) {
                    return false;
                }
                windowSize = apSet.getApSet().iterator().next().dataType.getLength();
                // TODO: this is a assumption, maybe need to remove in abandoned study.
                if (windowSize >= Global.currentProgram.getDefaultPointerSize()) {
                    return false;
                }
            }
            if (windowSize != apSet.getApSet().iterator().next().dataType.getLength()) {
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
        if (decompilerInferredTypes == null) {
            return false;
        }
        for (var dt: decompilerInferredTypes) {
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

    public void setFinalType(DataType dt) {
        finalType = dt;
        singleDerivedType = true;
    }

    public void updateGlobalMorphingDataType(DataType dt) {
        globalMorphingTypes.add(dt);
    }

    public boolean noMorphingTypes() {
        return globalMorphingTypes.isEmpty() && rangeMorphingTypes.isEmpty();
    }

    /**
     * Updates the range morphing types map by adding or merging the given DataTypes within the specified range.
     * This method handles the following scenarios:
     * 1. If the specified range (startOffset to endOffset) does not overlap with any existing range,
     *    it will be added directly to the rangeMorpingTypes map.
     * 2. If the specified range overlaps or is interlaced with any existing range, it will be merged with those ranges.
     * 3. If the specified range is completely contained within an existing range, the DataTypes will be added to that range.
     * 4. If the specified range completely contains one or more smaller ranges, those ranges will be merged into the new range.
     *
     * @param startOffset The start offset of the field range to be updated.
     * @param endOffset The end offset of the field range to be updated. It's important to note that the endOffset indicates the end of current field.
     * @param DTs The set of DataTypes to be associated with the specified range.
     */
    public void updateRangeMorphingDataType(long startOffset, long endOffset, Set<DataType> DTs) {
        Set<Range> rangesToMerge = new HashSet<>();
        Range containingRange = null;
        boolean isContained = false;

        for (var existingRange: rangeMorphingTypes.keySet()) {
            /* If new Range is completely contained within an existing range */
            if (existingRange.getStart() <= startOffset && existingRange.getEnd() >= endOffset) {
                containingRange = existingRange;
                isContained = true;
                break;
            }
            /* If new Range fully contains an existing range */
            else if (startOffset < existingRange.getStart() && endOffset > existingRange.getEnd()) {
                rangesToMerge.add(existingRange);
            }
            /* If intersection exists */
            else if ((startOffset < existingRange.getEnd() && startOffset > existingRange.getStart()) ||
                    (endOffset > existingRange.getStart() && endOffset < existingRange.getEnd())) {
                rangesToMerge.add(existingRange);
            }
        }

        if (isContained) {
            rangeMorphingTypes.get(containingRange).addAll(DTs);
        } else if (!rangesToMerge.isEmpty()) {
            long newStart = startOffset;
            long newEnd = endOffset;
            Set<DataType> mergedTypes = new HashSet<>(DTs);

            for (var range: rangesToMerge) {
                newStart = Math.min(newStart, range.getStart());
                newEnd = Math.max(newEnd, range.getEnd());
                mergedTypes.addAll(rangeMorphingTypes.get(range));
                rangeMorphingTypes.remove(range);
            }

            Range newRange = new Range(newStart, newEnd);
            rangeMorphingTypes.put(newRange, mergedTypes);
        } else {
            Range newRange = new Range(startOffset, endOffset);
            rangeMorphingTypes.put(newRange, DTs);
        }
    }

    /**
     * Similar to function `updateRangeMorphingDataType`
     * @param startOffset nest relationship's start offset
     * @param endOffset nest relationship's end offset
     */
    public void updateNestedRange(Long startOffset, Long endOffset) {
        Set<Range> rangesToMerge = new HashSet<>();
        boolean isContained = false;

        for (var existingRange: nestedRange) {
            /* If new Range is completely contained within an existing range */
            if (existingRange.getStart() <= startOffset && existingRange.getEnd() >= endOffset) {
                isContained = true;
                break;
            }
            /* If new Range fully contains an existing range */
            else if (startOffset < existingRange.getStart() && endOffset > existingRange.getEnd()) {
                rangesToMerge.add(existingRange);
            }
            /* If intersection exists */
            else if ((startOffset < existingRange.getEnd() && startOffset > existingRange.getStart()) ||
                    (endOffset > existingRange.getStart() && endOffset < existingRange.getEnd())) {
                rangesToMerge.add(existingRange);
            }
        }

        if (isContained) {
            return;
        } else if (!rangesToMerge.isEmpty()) {
            long newStart = startOffset;
            long newEnd = endOffset;

            for (var range: rangesToMerge) {
                newStart = Math.min(newStart, range.getStart());
                newEnd = Math.max(newEnd, range.getEnd());
                nestedRange.remove(range);
            }
            Range newRange = new Range(newStart, newEnd);
            nestedRange.add(newRange);
        } else {
            Range newRange = new Range(startOffset, endOffset);
            nestedRange.add(newRange);
        }
    }


    public void updateDecompilerInferredTypes(DataType dt) {
        if (decompilerInferredTypes == null) {
            decompilerInferredTypes = new HashSet<>();
        }
        decompilerInferredTypes.add(dt);
    }

    public boolean mustPrimitiveTypeAtOffset(long offset) {
        var aps = finalConstraint.fieldAccess.get(offset);
        if (ptrReference.containsKey(offset) || mayNestedSkeleton.containsKey(offset) ||
                !aps.isSameSizeType ||
                (aps.mostAccessedDT.getLength() >= Global.currentProgram.getDefaultPointerSize()) ) {
            return false;
        } else {
            return true;
        }
    }

    public void markInconsistentOffset(long offset) {
        inConsistentOffsets.add(offset);
    }

    public boolean isInconsistentOffset(long offset) {
        return inConsistentOffsets.contains(offset);
    }

    public boolean isInMorphingRange(long offset) {
        for (var range: rangeMorphingTypes.keySet()) {
            var start = range.getStart();
            var end = range.getEnd();
            if (offset >= start && offset < end) {
                return true;
            }
        }
        return false;
    }

    public boolean isInNestedRange(long offset) {
        for (var range: nestedRange) {
            var start = range.getStart();
            var end = range.getEnd();
            if (offset >= start && offset < end) {
                return true;
            }
        }
        return false;
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

        /* dump Layout */
        List<Long> sortedOffsets = Stream.of(finalConstraint.fieldAccess.keySet(), finalPtrReference.keySet(), finalNestedSkeleton.keySet())
                .flatMap(Collection::stream)
                .distinct()
                .sorted()
                .toList();
        StringBuilder layout = new StringBuilder();
        for (var offset: sortedOffsets) {
            layout.append(String.format("0x%x: ", offset));
            if (finalConstraint.fieldAccess.containsKey(offset)) {
                layout.append("\t");
                finalConstraint.fieldAccess.get(offset).getTypeFreq().forEach((dt, cnt) -> {
                    layout.append(String.format("%s(%d) ", dt.getName(), cnt));
                });
            }
            if (finalPtrReference.containsKey(offset)) {
                layout.append("\t");
                layout.append(String.format("Ptr Ref -> %s (%d)", finalPtrReference.get(offset), ptrLevel.get(offset)));
            }
            if (finalNestedSkeleton.containsKey(offset)) {
                layout.append("\t");
                layout.append(String.format("Nested -> %s", finalNestedSkeleton.get(offset)));
            }
            layout.append("\n");
        }
        Logging.info("Skeleton", "Layout:\n" + layout);
        /* end */

        Logging.info("Skeleton", "All Decompiler Inferred Types:\n" + decompilerInferredTypes);
        Logging.info("Skeleton", "Final Type:\n" + finalType);
        Logging.info("Skeleton", "Global Morphing Types:\n" + globalMorphingTypes);
        Logging.info("Skeleton", "Range Morphing Types:");
        for (var entry: rangeMorphingTypes.entrySet()) {
            var range = entry.getKey();
            var types = entry.getValue();
            Logging.info("Skeleton", String.format("Morphing Range (0x%x ~ 0x%x)", range.getStart(), range.getEnd()));
            for (var dt: types) {
                if (DataTypeHelper.isPointerToCompositeDataType(dt)) {
                    Logging.info("Skeleton", ((Pointer)dt).getDataType().toString());
                } else {
                    Logging.info("Skeleton", "Primitive: " + dt);
                }
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
            Logging.info("Skeleton", String.format("Strong merging skeletons %s and %s", skt1, skt2));
            var mergedConstraint = new TypeConstraint();
            var noConflict = true;
            for (var c: newConstraints) {
                Logging.info("Skeleton", String.format("Merging constraint:\n %s", c.dumpLayout(0)));
                noConflict = mergedConstraint.tryMerge(c);
                if (!noConflict) {
                    break;
                }
            }

            if (!noConflict) {
                Logging.warn("Skeleton", String.format("Failed to merge skeletons %s and %s", skt1, skt2));
                return Optional.empty();
            }


            Logging.info("Skeleton", String.format("Merged constraints:\n %s", mergedConstraint.dumpLayout(0)));
            newConstraints.clear();
            newConstraints.add(mergedConstraint);
            var newSkeleton = new Skeleton(newConstraints, newExprs);
            newSkeleton.hasMultiConstraints = false;
            return Optional.of(newSkeleton);
        } else {
            Logging.info("Skeleton", String.format("Weak merging skeletons %s and %s", skt1, skt2));
            for (var c: newConstraints) {
                Logging.info("Skeleton", c.dumpLayout(0));
            }
            var newSkeleton = new Skeleton(newConstraints, newExprs);
            newSkeleton.hasMultiConstraints = true;
            return Optional.of(newSkeleton);
        }
    }

}
