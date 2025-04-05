package typeforge.base.dataflow.constraint;

import typeforge.base.dataflow.Range;
import typeforge.base.dataflow.expression.NMAE;
import typeforge.utils.DataTypeHelper;
import typeforge.utils.Global;
import typeforge.utils.Logging;
import ghidra.program.model.data.DataType;
import typeforge.utils.TCHelper;

import java.util.*;
import java.util.stream.Stream;

public class TypeConstraint {
    public final java.util.UUID uuid = java.util.UUID.randomUUID();
    public final String shortUUID = java.util.UUID.randomUUID().toString().substring(0, 8);

    public Set<Skeleton> skeletons = new HashSet<>();
    public Skeleton finalSkeleton;
    public Set<NMAE> exprs = new HashSet<>();
    public Set<NMAE> variables = new HashSet<>();
    public boolean hasMultiSkeleton = false;

    public Map<Long, Set<TypeConstraint>> ptrReference = new HashMap<>();
    public Map<Long, TypeConstraint> finalPtrReference = new HashMap<>();
    public Map<Long, Integer> ptrLevel = new HashMap<>();
    public Map<Long, Set<TypeConstraint>> mayNestedConstraint = new HashMap<>();
    public Map<Long, TypeConstraint> finalNestedConstraint = new HashMap<>();

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
    public Set<Range> nestedRange = new HashSet<>();
    public Set<DataType> decompilerInferredTypes;
    public DataType finalType = null;

    public int size = -1;

    public TypeConstraint(Skeleton skeleton, Set<NMAE> exprs, boolean isFinal) {
        this.skeletons.add(skeleton);
        this.finalSkeleton = skeleton;
        this.exprs.addAll(exprs);
    }

    public TypeConstraint(Skeleton skeleton, Set<NMAE> exprs) {
        this.skeletons.add(skeleton);
        this.exprs.addAll(exprs);
    }

    public TypeConstraint(Set<Skeleton> skeletons, NMAE expr) {
        this.skeletons.addAll(skeletons);
        this.exprs.add(expr);
    }

    public TypeConstraint(Set<Skeleton> skeletons, Set<NMAE> exprs) {
        this.skeletons.addAll(skeletons);
        this.exprs.addAll(exprs);
    }

    public TypeConstraint(DataType dt) {
        this.finalType = dt;
    }

    public void addExpr(NMAE expr) {
        exprs.add(expr);
    }

    public void mergeConstraintFrom(TypeConstraint other) {
        this.skeletons.addAll(other.skeletons);
        this.exprs.addAll(other.exprs);
        this.hasMultiSkeleton = this.hasMultiSkeleton || other.hasMultiSkeleton;
    }

    public int getSkeletonsHash() {
        return skeletons.hashCode();
    }

    public void addPtrReference(long ptr, TypeConstraint skt) {
        ptrReference.computeIfAbsent(ptr, k -> new HashSet<>()).add(skt);
    }

    public boolean isMultiLevelMidPtr() {
        if (skeletons.size() > 1) { return false; }
        var constraint = skeletons.iterator().next();
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

    public Set<NMAE> getVariables() {
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
        /* Get the last element of fieldAccess */
        var maxSize = 0L;
        for (var entry: finalSkeleton.fieldAccess.entrySet()) {
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
        return ptrReference.isEmpty() && mayNestedConstraint.isEmpty();
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

    public boolean hasMultiNestedConstraint() {
        for (var entry: mayNestedConstraint.entrySet()) {
            if (entry.getValue().size() > 1) {
                return true;
            }
        }
        return false;
    }

    public boolean hasNestedConstraint() {
        return !mayNestedConstraint.isEmpty();
    }

    public boolean hasPtrReference() {
        return !finalPtrReference.isEmpty();
    }

    public boolean mayPrimitiveArray() {
        var fieldAccess = finalSkeleton.fieldAccess;
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
        return finalSkeleton.fieldAccess.size() == 1;
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
        var aps = finalSkeleton.fieldAccess.get(offset);
        if (ptrReference.containsKey(offset) || mayNestedConstraint.containsKey(offset) ||
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

    public Range getRangeNestedIn(long offset) {
        for (var range: nestedRange) {
            var start = range.getStart();
            var end = range.getEnd();
            if (offset >= start && offset < end) {
                return range;
            }
        }
        return null;
    }


    @Override
    public int hashCode() {
        return uuid.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof TypeConstraint) {
            return this.uuid.equals(((TypeConstraint) obj).uuid);
        }
        return false;
    }

    @Override
    public String toString() {
        return "TypeConstraint_" + shortUUID;
    }

    public void dumpInfo() {
        Logging.debug("TypeConstraint", " ------------------------------- Start --------------------------------- ");
        Logging.debug("TypeConstraint", this.toString());
        if (hasMultiSkeleton) {
            Logging.debug("TypeConstraint", String.format("C > 1, = %d", skeletons.size()));
        } else {
            Logging.debug("TypeConstraint", "C = 1");
        }
        Logging.debug("TypeConstraint", "Associated Exprs Count: " + exprs.size());
        Logging.debug("TypeConstraint", "All Exprs: " + exprs);
        Logging.debug("TypeConstraint", "Associated Variables Count: " + getVariables().size());
        Logging.debug("TypeConstraint", "All Variables: " + getVariables());

        /* dump Layout */
        List<Long> sortedOffsets = Stream.of(finalSkeleton.fieldAccess.keySet(), finalPtrReference.keySet(), finalNestedConstraint.keySet())
                .flatMap(Collection::stream)
                .distinct()
                .sorted()
                .toList();
        StringBuilder layout = new StringBuilder();
        for (var offset: sortedOffsets) {
            layout.append(String.format("0x%x: ", offset));
            if (finalSkeleton.fieldAccess.containsKey(offset)) {
                layout.append("\t");
                finalSkeleton.fieldAccess.get(offset).getTypeFreq().forEach((dt, cnt) -> {
                    layout.append(String.format("%s(%d) ", dt.getName(), cnt));
                });
            }
            if (finalPtrReference.containsKey(offset)) {
                layout.append("\t");
                layout.append(String.format("Ptr Ref -> %s (%d)", finalPtrReference.get(offset), ptrLevel.get(offset)));
            }
            if (finalNestedConstraint.containsKey(offset)) {
                layout.append("\t");
                layout.append(String.format("Nested -> %s", finalNestedConstraint.get(offset)));
            }
            layout.append("\t");
            layout.append(finalSkeleton.fieldExprMap.get(offset));
            layout.append("\n");
        }
        Logging.debug("TypeConstraint", "Layout:\n" + layout);
        /* end */

        Logging.debug("TypeConstraint", "All Decompiler Inferred Types:\n" + decompilerInferredTypes);
        Logging.debug("TypeConstraint", "Final Type:\n" + finalType);
        Logging.debug("TypeConstraint", String.format("Global Morphing Types (%d):\n%s", globalMorphingTypes.size(), globalMorphingTypes));
        Logging.debug("TypeConstraint", "Range Morphing Types:");
        for (var entry: rangeMorphingTypes.entrySet()) {
            var range = entry.getKey();
            var types = entry.getValue();
            Logging.debug("TypeConstraint", String.format("Morphing Range (0x%x ~ 0x%x) (%d)",
                    range.getStart(), range.getEnd(), types.size()));
            for (var dt: types) {
                Logging.debug("TypeConstraint", "\t" + dt);
            }
        }
        Logging.debug("TypeConstraint", " ------------------------------- End --------------------------------- ");
    }

    /**
     * Merge two constraints into a new constraint
     * @param tc1 merged constraint
     * @param tc2 merged constraint
     * @param isStrongMerge if true, merge all constraints in set into one constraint; otherwise just merge constraints set
     * @param isRelax if true, merge with relax; otherwise merge with strict
     * @return new merged constraint
     */
    public static Optional<TypeConstraint> mergeConstraints(TypeConstraint tc1, TypeConstraint tc2,
                                                            boolean isStrongMerge, boolean isRelax) {
        var newSkeletons = new HashSet<Skeleton>();
        var newExprs = new HashSet<NMAE>();
        newSkeletons.addAll(tc1.skeletons);
        newSkeletons.addAll(tc2.skeletons);
        newExprs.addAll(tc1.exprs);
        newExprs.addAll(tc2.exprs);

        if (isStrongMerge) {
            var mergedSkeleton = new Skeleton();
            var success = true;
            for (var skt: newSkeletons) {
                if (isRelax) {
                    success = mergedSkeleton.tryMergeLayoutRelax(skt);
                } else {
                    success = mergedSkeleton.tryMergeLayoutStrict(skt);
                }
                if (!success) {
                    break;
                }
            }

            if (!success) {
                Logging.warn("TypeConstraint", String.format("Failed to (%s) merge TypeConstraints %s and %s",
                        isStrongMerge ? "strong" : "weak", tc1, tc2));
                return Optional.empty();
            }

            var newTypeConstraint = new TypeConstraint(mergedSkeleton, newExprs, true);
            newTypeConstraint.hasMultiSkeleton = false;
            return Optional.of(newTypeConstraint);
        }
        else {
            var newTypeConstraint = new TypeConstraint(newSkeletons, newExprs);
            newTypeConstraint.hasMultiSkeleton = true;
            return Optional.of(newTypeConstraint);
        }
    }

    public static boolean checkConstraintConflict(TypeConstraint constraint1,
                                                  TypeConstraint constraint2,
                                                  boolean isRelax) {
        // Only check if both skeletons have single constraint
        if (constraint1.finalSkeleton != null && constraint2.finalSkeleton != null) {
            if (isRelax) {
                return TCHelper.checkFieldOverlapRelax(constraint1.finalSkeleton, constraint2.finalSkeleton);
            } else {
                return TCHelper.checkFieldOverlapStrict(constraint1.finalSkeleton, constraint2.finalSkeleton);
            }
        } else {
            // If one of the skeletons is null, we can not merge so return conflict
            return true;
        }
    }

}
