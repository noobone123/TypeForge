package typeforge.base.dataflow.constraint;

import ghidra.program.model.data.DataType;
import typeforge.base.dataflow.AccessPoints;
import typeforge.base.dataflow.expression.NMAE;
import typeforge.base.node.CallSite;
import typeforge.utils.Logging;

import java.util.*;

import typeforge.utils.TCHelper;

/**
 * Before final `TypeConstraint` is constructed, there are many partial constraints associated with NMAEs,
 * We call these intermediate temporary incomplete constraint `Skeleton`.
 */
public class Skeleton {

    public enum Attribute {
        SAME_ACCESS_ON_MULTI_OFFSETS,
        MAY_NESTED,
        POINTER,
        MAY_ARRAY_PTR,
        CODE_PTR,
    }

    public final UUID uuid;
    public final String shortUUID;
    /**
     * For a complexType, the fieldMap is a map from the offset of the field to the field's type.
     * Be careful that there maybe multiple dataTypes at the same offset in the fieldMap because of the union or array.
     * <code>
     * Skeleton {
     *     offset_1 : {type_1 : access_time, type_2 : access_time, ...},
     *     offset_2 : {type_1 : access_time, type_2 : access_time, ...},
     *     ...
     * }
     * </code>
     */
    public final TreeMap<Long, AccessPoints.APSet> fieldAccess;
    public final TreeMap<Long, HashSet<Attribute>> fieldAttrs;
    public final TreeMap<Long, HashSet<NMAE>> fieldExprMap;

    public final HashSet<Attribute> globalAttrs;
    /** The accessOffsets is a map which records the AP and the set of field offsets which are accessed by the AP */
    public final HashMap<AccessPoints.AP, HashSet<Long>> accessOffsets;

    /** Recording where this size information comes from */
    private final Set<SizeSource> sizeSources;

    public final Set<DataType> decompilerInferredTypes;

    public Set<Long> elementSize;

    /** If the Skeleton indicates a composite type */
    private boolean isComposite = false;


    public Skeleton() {
        uuid = UUID.randomUUID();
        shortUUID = uuid.toString().substring(0, 8);

        fieldAccess = new TreeMap<>();
        fieldExprMap = new TreeMap<>();

        fieldAttrs = new TreeMap<>();
        globalAttrs = new HashSet<>();
        accessOffsets = new HashMap<>();
        decompilerInferredTypes = new HashSet<>();
        elementSize = new HashSet<>();
        sizeSources = new HashSet<>();
    }

    public Skeleton(Skeleton other) {
        this.uuid = UUID.randomUUID();
        this.shortUUID = uuid.toString().substring(0, 8);

        this.fieldAccess = new TreeMap<>();
        for (Map.Entry<Long, AccessPoints.APSet> entry : other.fieldAccess.entrySet()) {
            this.fieldAccess.put(entry.getKey(), new AccessPoints.APSet(entry.getValue()));
        }

        this.fieldExprMap = new TreeMap<>();
        for (Map.Entry<Long, HashSet<NMAE>> entry : other.fieldExprMap.entrySet()) {
            this.fieldExprMap.put(entry.getKey(), new HashSet<>(entry.getValue()));
        }

        this.fieldAttrs = new TreeMap<>();
        for (Map.Entry<Long, HashSet<Attribute>> entry : other.fieldAttrs.entrySet()) {
            this.fieldAttrs.put(entry.getKey(), new HashSet<>(entry.getValue()));
        }

        this.globalAttrs = new HashSet<>(other.globalAttrs);

        this.accessOffsets = new HashMap<>();
        for (Map.Entry<AccessPoints.AP, HashSet<Long>> entry : other.accessOffsets.entrySet()) {
            this.accessOffsets.put(entry.getKey(), new HashSet<>(entry.getValue()));
        }

        this.decompilerInferredTypes = new HashSet<>(other.decompilerInferredTypes);

        this.sizeSources = new HashSet<>(other.sizeSources);
        this.isComposite = other.isComposite;

        this.elementSize = new HashSet<>(other.elementSize);
    }

    /** If the Skeleton is considered as a composite type
     * It's corresponding expr may be a pointer to a struct or union or array (including `char*`) */
    public void setComposite(boolean isComposite) {
        this.isComposite = isComposite;
    }

    public void addFieldAccess(long offset, AccessPoints.AP ap) {
        // update fieldAccess
        accessOffsets.putIfAbsent(ap, new HashSet<>());
        accessOffsets.get(ap).add(offset);
        fieldAccess.putIfAbsent(offset, new AccessPoints.APSet());
        if (fieldAccess.get(offset).addAP(ap)) {
            Logging.debug("Skeleton", String.format("Skeleton_%s adding field access: 0x%x -> %s", shortUUID, offset, ap.dataType));
        }
    }

    public void addFieldAccessForNestChecking(long offset, AccessPoints.APSet apSet) {
        // update fieldAccess
        fieldAccess.putIfAbsent(offset, apSet);
    }

    public void addFieldExpr(long offset, NMAE fieldAccessExpr) {
        fieldExprMap.putIfAbsent(offset, new HashSet<>());
        fieldExprMap.get(offset).add(fieldAccessExpr);
    }

    public void addFieldAttr(long offset, Attribute tag) {
        fieldAttrs.putIfAbsent(offset, new HashSet<>());
        fieldAttrs.get(offset).add(tag);
        Logging.debug("Skeleton", String.format("Skeleton_%s adding fieldTag: 0x%x -> %s", shortUUID, offset, tag));
    }

    public void addGlobalAttr(Attribute tag) {
        globalAttrs.add(tag);
        Logging.debug("Skeleton", String.format("Skeleton_%s adding globalTag: %s", shortUUID, tag));
    }

    public void removeFieldTag(long offset, Attribute tag) {
        if (fieldAttrs.containsKey(offset)) {
            fieldAttrs.get(offset).remove(tag);
        }
    }

    public void setSizeFromCallSite(long size, CallSite callSite) {
        var source = new SizeSource(size, callSite);
        sizeSources.add(source);
        Logging.debug("Skeleton", String.format("Skeleton_%s setting size 0x%x from callsite: %s", shortUUID, size, callSite));
    }

    public void setSizeFromExpr(long size, NMAE expr) {
        var source = new SizeSource(size, expr);
        sizeSources.add(source);
        Logging.debug("Skeleton", String.format("Skeleton_%s setting size 0x%x from expr: %s", shortUUID, size, expr));
    }

    public boolean hasSizeSource() {
        return !sizeSources.isEmpty();
    }

    public boolean hasMultiSizeSource() {
        return sizeSources.size() > 1;
    }

    public Set<SizeSource> getSizeSources() {
        return sizeSources;
    }

    public Optional<Long> getMaxSizeFromSource() {
        if (sizeSources.isEmpty()) {
            return Optional.empty();
        } else {
            return sizeSources.stream().map(SizeSource::getSize).max(Long::compareTo);
        }
    }

    public Long getMaxSizeFromFieldAccess() {
        if (fieldAccess.isEmpty()) return 0L;

        var maxSize = 0L;
        for (var entry: fieldAccess.entrySet()) {
            var offset = entry.getKey();
            var maxSizeAtOffset = entry.getValue().maxDTSize;
            if (offset + maxSizeAtOffset > maxSize) {
                maxSize = offset + maxSizeAtOffset;
            }
        }

        return maxSize;
    }

    public void strongUpdateSizeSources(SizeSource newSizeSource) {
        this.sizeSources.clear();
        this.sizeSources.add(newSizeSource);
    }

    public void updateSizeSource(SizeSource newSizeSource) {
        this.sizeSources.add(newSizeSource);
    }

    public void setElementSize(long size) {
        this.elementSize.add(size);
        Logging.debug("Skeleton", String.format("Skeleton_%s setting element size: %d", shortUUID, size));
    }

    public List<Long> collectFieldOffsets() {
        Set<Long> offsets = new HashSet<>(fieldAccess.keySet());
        offsets.addAll(fieldAttrs.keySet());
        List<Long> sortedOffset = new ArrayList<>(offsets);
        Collections.sort(sortedOffset);
        return sortedOffset;
    }

    public int getFieldMaxSize(long offset) {
        int maxSize = 0;
        for (AccessPoints.AP ap : fieldAccess.get(offset).getApSet()) {
            maxSize = Math.max(maxSize, ap.dataType.getLength());
        }
        return maxSize;
    }

    /**
     * Merge two Skeletons into a new Skeleton.
     * This merging will not change the original Skeleton's structure and relations
     * @param other the other Skeleton to merge
     * @return false if there is a conflict, true otherwise
     */
    public boolean tryMergeLayoutStrict(Skeleton other) {
        if (TCHelper.checkFieldOverlapStrict(this, other)) {
            return false;
        }
        mergeOther(other);
        return true;
    }

    public boolean tryMergeLayoutRelax(Skeleton other) {
        if (TCHelper.checkFieldOverlapRelax(this, other)) {
            return false;
        }
        mergeOther(other);
        return true;
    }

    /**
     * Merge other Skeleton's info into the current Skeleton
     * @param other The other Skeleton to merge
     */
    public void mergeOther(Skeleton other) {
        // merging fieldAccess
        other.fieldAccess.forEach((offset, aps) -> {
            this.fieldAccess.putIfAbsent(offset, new AccessPoints.APSet());
            this.fieldAccess.get(offset).addAll(aps.getApSet());
        });

        // merging fieldAttrs
        other.fieldAttrs.forEach((offset, tags) -> {
            this.fieldAttrs.putIfAbsent(offset, new HashSet<>());
            this.fieldAttrs.get(offset).addAll(tags);
        });

        // Merging fieldExpr
        other.fieldExprMap.forEach((offset, exprs) -> {
            this.fieldExprMap.putIfAbsent(offset, new HashSet<>());
            this.fieldExprMap.get(offset).addAll(exprs);
        });

        // Merging global attributes
        this.globalAttrs.addAll(other.globalAttrs);

        // Merging accessOffsets
        other.accessOffsets.forEach((ap, offsets) -> {
            this.accessOffsets.putIfAbsent(ap, new HashSet<>());
            this.accessOffsets.get(ap).addAll(offsets);
        });

        // Merging size
        this.sizeSources.addAll(other.sizeSources);
        this.elementSize.addAll(other.elementSize);

        // Merging decompiler inferred types
        this.decompilerInferredTypes.addAll(other.decompilerInferredTypes);
    }

    public String getName() {
        return shortUUID;
    }

    @Override
    public String toString() {
        return "Skeleton_" + getName();
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

    public boolean checkSizeConflict(SizeSource other) {
        if (sizeSources.isEmpty()) {
            return false;
        } else {
            var sizes = new HashSet<Long>();
            for (var sizeSource: sizeSources) {
                sizes.add(sizeSource.getSize());
            }

            var otherSize = other.getSize();
            return !sizes.contains(otherSize);
        }
    }

    public boolean isEmpty() {
        return fieldAccess.isEmpty() && fieldAttrs.isEmpty() &&
                decompilerInferredTypes.isEmpty() && sizeSources.isEmpty();
    }

    public void addDecompilerInferredType(DataType dataType) {
        decompilerInferredTypes.add(dataType);
        Logging.debug("Skeleton", String.format("Skeleton_%s adding polymorphicType: %s", shortUUID, dataType.getName()));
    }

    public Set<DataType> getDecompilerInferredTypes() {
        return decompilerInferredTypes;
    }

    public int getAllFieldsAccessCount() {
        int count = 0;
        for (var aps: fieldAccess.values()) {
            count += aps.getAPCount();
        }
        return count;
    }

    /** Dump current Skeleton's layout */
    public String dumpLayout(int prefixTabCnt) {
        StringBuilder sb = new StringBuilder();
        String prefixTab = "\t".repeat(prefixTabCnt);
        sb.append(prefixTab).append("Skeleton_").append(shortUUID).append(":\n");
        sb.append(prefixTab).append("DecompilerInferred: ").append(decompilerInferredTypes).append("\n");
        fieldAccess.forEach((offset, aps) -> {
            /* Group the aps into Map[dataType, accessCount] */
            sb.append(prefixTab).append("\t");
            sb.append(String.format("0x%x: ", offset));
            sb.append("\t");
            aps.getTypeFreq().forEach((dataType, count) -> {
                sb.append(String.format("%s(%d) ", dataType.getName(), count));
            });
            sb.append("\n");
        });
        return sb.toString();
    }
}
