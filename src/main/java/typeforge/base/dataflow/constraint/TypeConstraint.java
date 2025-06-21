package typeforge.base.dataflow.constraint;

import ghidra.program.model.data.Array;
import typeforge.base.dataflow.Range;
import typeforge.base.dataflow.expression.NMAE;
import typeforge.utils.Global;
import typeforge.utils.Logging;
import ghidra.program.model.data.DataType;
import typeforge.utils.TCHelper;

import java.util.*;
import java.util.stream.Stream;

public class TypeConstraint {
    public final java.util.UUID uuid = java.util.UUID.randomUUID();
    public final String shortUUID = java.util.UUID.randomUUID().toString().substring(0, 8);

    public Skeleton innerSkeleton;
    public Set<NMAE> exprs = new HashSet<>();
    public Set<NMAE> variables = new HashSet<>();
    public long size = -1;

    public Map<Long, Set<TypeConstraint>> ptrReference = new HashMap<>();
    public Map<Long, TypeConstraint> finalPtrReference = new HashMap<>();
    public Map<Long, Integer> ptrLevel = new HashMap<>();
    public Map<Long, Set<TypeConstraint>> nestedConstraint = new HashMap<>();
    public Map<Long, TypeConstraint> finalNestedConstraint = new HashMap<>();

    public Set<DataType> decompilerInferredCompositeTypes = new HashSet<>();

    public Set<Long> inConsistentOffsets = new HashSet<>();

    public boolean isPointerToPrimitive = false;
    public boolean mayPointerToPrimitiveArray = false;
    public boolean isMultiLevelMidPtr = false;
    /**
     *  Following Fields should be updated after all TypeConstraints are merged, handled and confirmed
     *  If there are multiple fields in the Constraint need to generate and assessment (We call it MorphingPoint)
     *  In order to reduce time complexity, we try to assess each morphRange and choose the best one in each morphRange.
     *  And finally, we will synthesize the final result based on every best choice in each morphRange.
     */
    public Set<DataType> globalMorphingTypes = new HashSet<>();
    public Map<Range, Set<DataType>> rangeMorphingTypes = new HashMap<>();
    public Set<Range> nestedRange = new HashSet<>();
    public DataType finalType = null;

    /**
     * Create a new TypeConstraint based on the given skeleton and associated expressions
     */
    public TypeConstraint(Skeleton skeleton, Set<NMAE> exprs) {
        this.innerSkeleton = skeleton;
        this.exprs.addAll(exprs);
        this.decompilerInferredCompositeTypes.addAll(innerSkeleton.getDecompilerInferredCompositeTypes());
        setVariables();
        // Following order should not be changed.
        // As setMaxSize depends on handleFieldAPSet
        handleFieldAPSet();
        setMaxSize();

        if (innerSkeleton.fieldAccess.size() == 1
                && innerSkeleton.fieldAccess.get(0L) != null) {
            isPointerToPrimitive = true;
        }
    }

    /**
     * Merge two TypeConstraints into a new TypeConstraint.
     * If successfully merged, return the new TypeConstraint.
     * If failed, return an empty Optional.
     */
    public static Optional<TypeConstraint> mergeConstraint(TypeConstraint tc1, TypeConstraint tc2,
                                                    boolean isRelax) {
        // Step1: merge innerSkeleton first
        var skt1 = tc1.innerSkeleton;
        var skt2 = tc2.innerSkeleton;
        var mergedSkt = new Skeleton(skt1);
        boolean success = true;
        if (isRelax) {
            success = mergedSkt.tryMergeLayoutRelax(skt2);
        } else {
            success = mergedSkt.tryMergeLayoutStrict(skt2);
        }

        if (!success) {
            Logging.warn("TypeConstraint",
                    String.format("Failed to merge Skeletons %s and %s", skt1, skt2));
            return Optional.empty();
        }


        // Step2: merge expressions
        var newExprs = new HashSet<NMAE>();
        newExprs.addAll(tc1.exprs);
        newExprs.addAll(tc2.exprs);

        var newTypeConstraint = new TypeConstraint(mergedSkt, newExprs);

        // Step3: also merge other fields
        newTypeConstraint.ptrReference.putAll(tc1.ptrReference);
        newTypeConstraint.ptrReference.putAll(tc2.ptrReference);
        newTypeConstraint.finalPtrReference.putAll(tc1.finalPtrReference);
        newTypeConstraint.finalPtrReference.putAll(tc2.finalPtrReference);
        newTypeConstraint.ptrLevel.putAll(tc1.ptrLevel);
        newTypeConstraint.ptrLevel.putAll(tc2.ptrLevel);
        newTypeConstraint.nestedConstraint.putAll(tc1.nestedConstraint);
        newTypeConstraint.nestedConstraint.putAll(tc2.nestedConstraint);
        newTypeConstraint.finalNestedConstraint.putAll(tc1.finalNestedConstraint);
        newTypeConstraint.finalNestedConstraint.putAll(tc2.finalNestedConstraint);

        return Optional.of(newTypeConstraint);
    }

    /**
     * Find the member's datatype, min/max datatype size and most accessed datatype
     */
    public void handleFieldAPSet() {
        for (var entry: innerSkeleton.fieldAccess.entrySet()) {
            var apSet = entry.getValue();
            if (apSet != null) {
                apSet.postHandle();
            }
        }
    }

    /**
     * if there are multi-level pointer references like `**a`.
     * In TypeConstraint, a's constraint may look like
     * a --> mid-ptr -> layout
     * However, we want a --ptr-level(2)--> layout, so mid-ptr should be identified and removed
     * @return If current skeleton is a multi-level mid pointer
     */
    public boolean checkMultiLevelMidPtr() {
        var skeleton = innerSkeleton;
        if (skeleton.fieldAccess.size() != 1) { return false; }
        if (skeleton.fieldAccess.get(0L) == null) { return false; }
        var apSet = skeleton.fieldAccess.get(0L);
        if (!apSet.isSameSizeType) { return false; }
        if (apSet.mostAccessedDT.getLength() != Global.currentProgram.getDefaultPointerSize()) { return false; }

        if (finalPtrReference.get(0L) != null) {
            isMultiLevelMidPtr = true;
            mayPointerToPrimitiveArray = false;
            isPointerToPrimitive = false;
            finalType = null;
            return true;
        } else {
            isMultiLevelMidPtr = false;
            return false;
        }
    }

    /**
     * Get the size of current skeleton, we consider the
     * max of (finalConstraint.fieldAccess.size(), finalConstraint.fieldAccess.size() + nestedSkeleton.size())
     */
    public void setMaxSize() {
        /* Get the last element of fieldAccess */
        var maxSize = 0L;
        for (var entry: innerSkeleton.fieldAccess.entrySet()) {
            var offset = entry.getKey();
            var maxSizeAtOffset = entry.getValue().maxDTSize;
            if (offset + maxSizeAtOffset > maxSize) {
                maxSize = offset + maxSizeAtOffset;
            }
        }

        /* Get the size from sizeSource */
        var sizeFromSource = innerSkeleton.getMaxSizeFromSource();
        if (sizeFromSource.isPresent()) {
            var sizeSource = sizeFromSource.get();
            size = (sizeSource > maxSize ? sizeSource : maxSize);
        } else {
            size = maxSize;
        }
    }

    public int getMaxSize() {
        return (int) size;
    }

    public void setVariables() {
        for (var expr: exprs) {
            if (expr.isVariable()) {
                variables.add(expr);
            }
        }
    }

    public Set<NMAE> getVariables() {
        return variables;
    }

    /**
     * If current skeleton has no pointer reference or nested skeletons, it is independent
     * @return true if independent
     */
    public boolean isIndependent() {
        return ptrReference.isEmpty() && nestedConstraint.isEmpty();
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
        for (var entry: nestedConstraint.entrySet()) {
            if (entry.getValue().size() > 1) {
                return true;
            }
        }
        return false;
    }

    public boolean hasFinalNestedConstraint() {
        return !finalNestedConstraint.isEmpty();
    }

    public boolean hasFinalPtrReference() {
        return !finalPtrReference.isEmpty();
    }

    public boolean mayPointerToPrimitive() {
        return isPointerToPrimitive;
    }

    public boolean hasOneField() {
        return innerSkeleton.fieldAccess.size() == 1;
    }

    public boolean hasDecompilerInferredCompositeType() {
        return !decompilerInferredCompositeTypes.isEmpty();
    }

    public boolean onlyArraysInDecompilerInferredCompositeTypes() {
        for (var dt: decompilerInferredCompositeTypes) {
            if (dt instanceof Array) {
                continue;
            } else {
                return false;
            }
        }
        return true;
    }

    public boolean hasMultipleDecompilerInferredSizes() {
        var sizes = new HashSet<Integer>();
        for (var dt: decompilerInferredCompositeTypes) {
            var dtSize = dt.getLength();
            if (dtSize > 0) {
                sizes.add(dtSize);
            }
        }
        return sizes.size() > 1;
    }

    public boolean noFieldAccess() {
        return innerSkeleton.fieldAccess.isEmpty();
    }

    public boolean hasMultipleNonPointerSameSizeMembers() {
        var memberCount = innerSkeleton.fieldAccess.size();
        if (memberCount <= 1) {
            return false;
        }

        var firstMemberAPSet = innerSkeleton.fieldAccess.get(0L);
        if (firstMemberAPSet == null || firstMemberAPSet.apSet.isEmpty()) {
            return false;
        }

        var firstMemberSize = firstMemberAPSet.mostAccessedDT.getLength();
        // We only consider char, shot, int, as other may be pointers
        if (firstMemberSize >= Global.currentProgram.getDefaultPointerSize()) {
            return false;
        }

        for (var offset: innerSkeleton.fieldAccess.keySet()) {
            var apSet = innerSkeleton.fieldAccess.get(offset);
            if (!apSet.isSameSizeType) { return false; }
            var fieldSize = apSet.mostAccessedDT.getLength();
            if (fieldSize != firstMemberSize) {
                return false;
            }
        }

        return true;
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

    public boolean mustPrimitiveTypeAtOffset(long offset) {
        var aps = innerSkeleton.fieldAccess.get(offset);
        if (ptrReference.containsKey(offset) || nestedConstraint.containsKey(offset) ||
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

    public boolean isEmpty() {
        return innerSkeleton.isEmpty();
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
        Logging.debug("TypeConstraint", "Associated Exprs Count: " + exprs.size());
        Logging.debug("TypeConstraint", "All Exprs: " + exprs);
        Logging.debug("TypeConstraint", "Associated Variables Count: " + getVariables().size());
        Logging.debug("TypeConstraint", "All Variables: " + getVariables());

        /* dump Layout */
        List<Long> sortedOffsets = Stream.of(innerSkeleton.fieldAccess.keySet(), finalPtrReference.keySet(), finalNestedConstraint.keySet())
                .flatMap(Collection::stream)
                .distinct()
                .sorted()
                .toList();
        StringBuilder layout = new StringBuilder();
        for (var offset: sortedOffsets) {
            layout.append(String.format("0x%x: ", offset));
            if (innerSkeleton.fieldAccess.containsKey(offset)) {
                layout.append("\t");
                innerSkeleton.fieldAccess.get(offset).getTypeFreq().forEach((dt, cnt) -> {
                    layout.append(String.format("%s(%d) ", dt.getName(), cnt));
                });
            }
            if (finalPtrReference.containsKey(offset)) {
                layout.append("\t");
                layout.append(String.format("PtrRef -> %s (%d)", finalPtrReference.get(offset), ptrLevel.get(offset)));
            }
            if (finalNestedConstraint.containsKey(offset)) {
                layout.append("\t");
                layout.append(String.format("Nested -> %s", finalNestedConstraint.get(offset)));
            }
            layout.append("\t");
            layout.append(innerSkeleton.fieldExprMap.get(offset));
            layout.append("\n");
        }
        Logging.debug("TypeConstraint", "Layout:\n" + layout);
        /* end */

        Logging.debug("TypeConstraint", "All Decompiler Inferred Types:\n" + decompilerInferredCompositeTypes);
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

    public static boolean checkConstraintConflict(TypeConstraint constraint1,
                                                  TypeConstraint constraint2,
                                                  boolean isRelax) {
        // Only check if both skeletons have single constraint
        if (constraint1.innerSkeleton != null && constraint2.innerSkeleton != null) {
            if (isRelax) {
                return TCHelper.checkFieldOverlapRelax(constraint1.innerSkeleton, constraint2.innerSkeleton);
            } else {
                return TCHelper.checkFieldOverlapStrict(constraint1.innerSkeleton, constraint2.innerSkeleton);
            }
        } else {
            // If one of the skeletons is null, we can not merge so return conflict
            return true;
        }
    }

    public static boolean checkNestConflict(TypeConstraint nester, TypeConstraint nestee,
                                            long offset, boolean isRelax) {
        var nesterSkt = nester.innerSkeleton;
        var nesteeSkt = nestee.innerSkeleton;
        var nestedCandidate = new Skeleton(nesteeSkt, offset);

        if (isRelax) {
            return !TCHelper.checkFieldOverlapRelax(nesterSkt, nestedCandidate);
        } else {
            return !TCHelper.checkFieldOverlapStrict(nesterSkt, nestedCandidate);
        }
    }
}
