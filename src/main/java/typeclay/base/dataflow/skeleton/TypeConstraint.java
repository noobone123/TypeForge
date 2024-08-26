package typeclay.base.dataflow.skeleton;

import typeclay.base.dataflow.AccessPoints;
import typeclay.base.dataflow.SymbolExpr.SymbolExpr;
import typeclay.base.dataflow.types.TypeDescriptor;
import typeclay.utils.Logging;

import java.util.*;

import typeclay.utils.TCHelper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class TypeConstraint {

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
     * TypeConstraints {
     *     offset_1 : {type_1 : access_time, type_2 : access_time, ...},
     *     offset_2 : {type_1 : access_time, type_2 : access_time, ...},
     *     ...
     * }
     * </code>
     */
    public final TreeMap<Long, AccessPoints.APSet> fieldAccess;
    public final TreeMap<Long, HashSet<Attribute>> fieldAttrs;
    public final TreeMap<Long, HashSet<SymbolExpr>> fieldExprMap;

    public final HashSet<Attribute> globalAttrs;
    /** The accessOffsets is a map which records the AP and the set of field offsets which are accessed by the AP */
    public final HashMap<AccessPoints.AP, HashSet<Long>> accessOffsets;

    public final Set<TypeDescriptor> polymorphicTypes;

    public Set<Long> totalSize;
    public Set<Long> elementSize;

    public TypeConstraint() {
        uuid = UUID.randomUUID();
        shortUUID = uuid.toString().substring(0, 8);

        fieldAccess = new TreeMap<>();
        fieldExprMap = new TreeMap<>();

        fieldAttrs = new TreeMap<>();
        globalAttrs = new HashSet<>();
        accessOffsets = new HashMap<>();
        polymorphicTypes = new HashSet<>();
        totalSize = new HashSet<>();
        elementSize = new HashSet<>();
    }

    public TypeConstraint(TypeConstraint other) {
        this.uuid = UUID.randomUUID();
        this.shortUUID = uuid.toString().substring(0, 8);

        this.fieldAccess = new TreeMap<>();
        for (Map.Entry<Long, AccessPoints.APSet> entry : other.fieldAccess.entrySet()) {
            this.fieldAccess.put(entry.getKey(), new AccessPoints.APSet(entry.getValue()));
        }

        this.fieldExprMap = new TreeMap<>();
        for (Map.Entry<Long, HashSet<SymbolExpr>> entry : other.fieldExprMap.entrySet()) {
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

        this.polymorphicTypes = new HashSet<>(other.polymorphicTypes);

        this.totalSize = new HashSet<>(other.totalSize);

        this.elementSize = new HashSet<>(other.elementSize);
    }

    public void addFieldAccess(long offset, AccessPoints.AP ap) {
        // update fieldAccess
        accessOffsets.putIfAbsent(ap, new HashSet<>());
        accessOffsets.get(ap).add(offset);
        fieldAccess.putIfAbsent(offset, new AccessPoints.APSet());
        if (fieldAccess.get(offset).addAP(ap)) {
            Logging.info("TypeConstraint", String.format("Constraint_%s adding field access: 0x%x -> %s", shortUUID, offset, ap.dataType));
        }
    }

    public void addFieldExpr(long offset, SymbolExpr fieldAccessExpr) {
        fieldExprMap.putIfAbsent(offset, new HashSet<>());
        fieldExprMap.get(offset).add(fieldAccessExpr);
    }

    public void addFieldAttr(long offset, Attribute tag) {
        fieldAttrs.putIfAbsent(offset, new HashSet<>());
        fieldAttrs.get(offset).add(tag);
        Logging.info("TypeConstraint", String.format("Constraint_%s adding fieldTag: 0x%x -> %s", shortUUID, offset, tag));
    }

    public void addGlobalAttr(Attribute tag) {
        globalAttrs.add(tag);
        Logging.info("TypeConstraint", String.format("Constraint_%s adding globalTag: %s", shortUUID, tag));
    }

    public void removeFieldTag(long offset, Attribute tag) {
        if (fieldAttrs.containsKey(offset)) {
            fieldAttrs.get(offset).remove(tag);
        }
    }

    public void setTotalSize(long size) {
        this.totalSize.add(size);
        Logging.info("TypeConstraint", String.format("Constraint_%s setting total size: %d", shortUUID, size));
    }

    public void setElementSize(long size) {
        this.elementSize.add(size);
        Logging.info("TypeConstraint", String.format("Constraint_%s setting element size: %d", shortUUID, size));
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
     * Merge two TypeConstraints into a new TypeConstraint.
     * This merging will not change the original TypeConstraints' structure and relations
     * @param other the other TypeConstraint to merge
     * @return false if there is a conflict, true otherwise
     */
    public boolean tryMerge(TypeConstraint other) {
        if (TCHelper.checkFieldOverlap(this, other)) {
            return false;
        }
        mergeOther(other);
        return true;
    }


    /**
     * Merge other TypeConstraint's info into the current TypeConstraint
     * @param other The other TypeConstraint to merge
     */
    public void mergeOther(TypeConstraint other) {
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
        this.totalSize.addAll(other.totalSize);
        this.elementSize.addAll(other.elementSize);

        // Merging polymorphicTypes
        this.polymorphicTypes.addAll(other.polymorphicTypes);
    }

    public String getName() {
        return shortUUID;
    }

    @Override
    public String toString() {
        return "Constraint_" + getName();
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

    public boolean isEmpty() {
        return fieldAccess.isEmpty() && fieldAttrs.isEmpty() && polymorphicTypes.isEmpty() && totalSize.isEmpty() && elementSize.isEmpty();
    }

    public void addPolymorphicType(TypeDescriptor type) {
        polymorphicTypes.add(type);
        Logging.info("TypeConstraint", String.format("Constraint_%s adding polymorphicType: %s", shortUUID, type.getName()));
    }

    public int getAllFieldsAccessCount() {
        int count = 0;
        for (var aps: fieldAccess.values()) {
            count += aps.getAPCount();
        }
        return count;
    }

    /** Dump current TypeConstraint's layout */
    public String dumpLayout(int prefixTabCnt) {
        StringBuilder sb = new StringBuilder();
        String prefixTab = "\t".repeat(prefixTabCnt);
        sb.append(prefixTab).append("Constraint_").append(shortUUID).append(":\n");
        sb.append(prefixTab).append("PolyTypes: ").append(polymorphicTypes).append("\n");
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
