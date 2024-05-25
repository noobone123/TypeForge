package blueprint.base.dataflow.constraints;

import blueprint.base.dataflow.AccessPoints;
import blueprint.utils.Logging;

import java.util.*;

public class TypeConstraint implements TypeDescriptor {
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
    public final TreeMap<Long, HashMap<TypeDescriptor, Integer>> fieldMap;
    public final TreeMap<Long, HashSet<String>> tags;
    public final TreeMap<Long, Long> ptrLevel;

    /** The accessOffsets is a map which records the AP and the set of field offsets which are accessed by the AP */
    public final HashMap<AccessPoints.AP, HashSet<Long>> accessOffsets;
    public long size = 0;

    public final UUID uuid;
    public final String shortUUID;

    public TypeConstraint() {
        fieldMap = new TreeMap<>();
        tags = new TreeMap<>();
        ptrLevel = new TreeMap<>();

        accessOffsets = new HashMap<>();
        uuid = UUID.randomUUID();
        shortUUID = uuid.toString().substring(0, 8);
    }


    public void build() {
        accessOffsets.forEach((ap, offsets) -> {
            if (offsets.size() > 1) {
                for (var offset : offsets) {
                    addTag(offset, "SAME_ACCESS");
                }
            }
        });
    }

    public void addOffsetConstraint(long offset, AccessPoints.AP ap) {
        accessOffsets.putIfAbsent(ap, new HashSet<>());
        accessOffsets.get(ap).add(offset);
        addField(offset, ap.dataType);
    }

    public void addField(long offset, TypeDescriptor type) {
        fieldMap.putIfAbsent(offset, new HashMap<>());
        fieldMap.get(offset).put(type, fieldMap.get(offset).getOrDefault(type, 0) + 1);
        Logging.info(String.format("[Constraint] %s adding field: 0x%x -> %s", shortUUID, offset, type.getName()));
    }

    public void setPtrLevel(long offset, long newLevel) {
        if (ptrLevel.containsKey(offset)) {
            if (ptrLevel.get(offset) < newLevel) {
                ptrLevel.put(offset, newLevel);
                Logging.info(String.format("[Constraint] %s setting new ptrLevel for 0x%x: %d", shortUUID, offset, newLevel));
            }
        } else {
            ptrLevel.put(offset, newLevel);
            Logging.info(String.format("[Constraint] %s setting new ptrLevel for 0x%x: %d", shortUUID, offset, newLevel));
        }
    }

    public void addTag(long offset, String tag) {
        tags.putIfAbsent(offset, new HashSet<>());
        tags.get(offset).add(tag);
    }

    public void removeTag(long offset, String tag) {
        if (tags.containsKey(offset)) {
            tags.get(offset).remove(tag);
        }
    }

    public void setSize(long size) {
        if (size != this.size) {
            this.size = size;
            Logging.info(String.format("[Constraint] %s setting new size: %d", shortUUID, size));
        }
    }

    public void merge(TypeConstraint other) {
        // Merging fields from other Constraint
        other.fieldMap.forEach((offset, typeMap) -> {
            if (!this.fieldMap.containsKey(offset)) {
                this.fieldMap.put(offset, new HashMap<>(typeMap));
            } else {
                typeMap.forEach((type, count) ->
                        this.fieldMap.get(offset).merge(type, count, Integer::sum));
            }
        });

        // Merging tags
        other.tags.forEach((offset, tagSet) -> {
            this.tags.putIfAbsent(offset, new HashSet<>());
            this.tags.get(offset).addAll(tagSet);
        });
    }


    @Override
    public String getName() {
        return shortUUID;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Constraint_" + shortUUID + " {\n");
        if (size != 0) {
            sb.append("Size: ").append(size).append("\n");
        }
        fieldMap.forEach((offset, typeMap) -> {
            sb.append("0x").append(Long.toHexString(offset)).append(" : {");
            typeMap.forEach((type, count) -> sb.append(type.getName()).append(" : ").append(count).append(", "));
            sb.append("},   ");
            if (tags.containsKey(offset)) {
                sb.append("Tags: ");
                tags.get(offset).forEach(tag -> sb.append(tag).append(", "));
            }
            if (ptrLevel.containsKey(offset)) {
                sb.append("PtrLevel: ").append(ptrLevel.get(offset));
            }
            sb.append("\n");
        });
        sb.append("}");
        return sb.toString();
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
}
