package blueprint.base.dataflow.type;

import blueprint.base.dataflow.FieldEntry;

import java.util.HashMap;
import java.util.HashSet;
import java.util.TreeMap;
import java.util.UUID;

public class ComplexType implements GeneralType {
    /**
     * For a complexType, the fieldMap is a map from the offset of the field to the field's type.
     * Be careful that there maybe multiple dataTypes at the same offset in the fieldMap because of the union or array.
     * <code>
     * ComplexType {
     *     offset_1 : {type_1 : access_time, type_2 : access_time, ...},
     *     offset_2 : {type_1 : access_time, type_2 : access_time, ...},
     *     ...
     * }
     * </code>
     */
    public final TreeMap<Long, HashMap<GeneralType, Integer>> fieldMap;
    public final TreeMap<Long, HashSet<String>> tags;
    public final UUID uuid;
    public final String shortUUID;

    public ComplexType() {
        fieldMap = new TreeMap<>();
        tags = new TreeMap<>();
        uuid = UUID.randomUUID();
        shortUUID = uuid.toString().substring(0, 8);
    }

    public void addField(long offset, GeneralType type) {
        fieldMap.putIfAbsent(offset, new HashMap<>());
        fieldMap.get(offset).put(type, fieldMap.get(offset).getOrDefault(type, 0) + 1);
    }

    @Override
    public String getTypeName() {
        return shortUUID;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("ComplexType_" + shortUUID + " {\n");
        fieldMap.forEach((offset, typeMap) -> {
            sb.append("0x").append(Long.toHexString(offset)).append(" : {");
            typeMap.forEach((type, count) -> sb.append(type.getTypeName()).append(" : ").append(count).append(", "));
            sb.append("}, \n");
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
        if (obj instanceof ComplexType) {
            return this.uuid.equals(((ComplexType) obj).uuid);
        }
        return false;
    }

    public void merge(ComplexType other) {
        // Merging fields from other ComplexType
        other.fieldMap.forEach((offset, typeMap) -> {
            if (!this.fieldMap.containsKey(offset)) {
                this.fieldMap.put(offset, new HashMap<>(typeMap));
            } else {
                typeMap.forEach((type, count) ->
                        this.fieldMap.get(offset).merge(type, count, Integer::sum));
            }
        });

        // Optional: Merging tags if necessary
        other.tags.forEach((offset, tagSet) -> {
            this.tags.putIfAbsent(offset, new HashSet<>());
            this.tags.get(offset).addAll(tagSet);
        });
    }
}
