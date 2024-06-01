package blueprint.base.dataflow.constraints;

import blueprint.base.dataflow.AccessPoints;
import blueprint.utils.Logging;

import java.util.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class TypeConstraint implements TypeDescriptor {

    public enum Attribute {
        ARGUMENT,
        MULTI_ACCESS,
        MAY_ARRAY,
        MAY_NESTED,
        ARRAY,
        STRUCT,
        UNION,
        LOCAL,
        GLOBAL
    }

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
    public final TreeMap<Long, HashSet<Attribute>> fieldTags;
    public final TreeMap<Long, Long> ptrLevel;

    /** The accessOffsets is a map which records the AP and the set of field offsets which are accessed by the AP */
    public final HashMap<AccessPoints.AP, HashSet<Long>> accessOffsets;

    public Set<Attribute> globalTags;
    public Set<Long> totalSize;
    public Set<Long> elementSize;

    /** The referenceTo is a map from current TypeConstraint's offset to the referenced TypeConstraint */
    public final HashMap<Long, HashSet<TypeConstraint>> referenceTo;
    /** The referencedBy is a map which records which TypeConstraint references the current TypeConstraint and the set of referenced offsets */
    public final HashMap<TypeConstraint, HashSet<Long>> referencedBy;

    public final UUID uuid;
    public final String shortUUID;

    public TypeConstraint() {
        fieldMap = new TreeMap<>();
        fieldTags = new TreeMap<>();
        ptrLevel = new TreeMap<>();

        accessOffsets = new HashMap<>();
        uuid = UUID.randomUUID();
        shortUUID = uuid.toString().substring(0, 8);

        referenceTo = new HashMap<>();
        referencedBy = new HashMap<>();

        globalTags = new HashSet<>();
        this.totalSize = new HashSet<>();
        this.elementSize = new HashSet<>();
    }


    public void build() {
        accessOffsets.forEach((ap, offsets) -> {
            if (offsets.size() > 1) {
                for (var offset : offsets) {
                    // If one pcode Access Multiple fields, we should add a tag to the field
                    addFieldTag(offset, Attribute.MULTI_ACCESS);
                }
            }
        });
    }

    public void addFieldConstraint(long offset, AccessPoints.AP ap) {
        accessOffsets.putIfAbsent(ap, new HashSet<>());
        accessOffsets.get(ap).add(offset);
        addOffsetTypeConstraint(offset, ap.dataType);
    }

    public void addOffsetTypeConstraint(long offset, TypeDescriptor type) {
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

    public void addFieldTag(long offset, Attribute tag) {
        fieldTags.putIfAbsent(offset, new HashSet<>());
        fieldTags.get(offset).add(tag);
    }

    public void removeFieldTag(long offset, Attribute tag) {
        if (fieldTags.containsKey(offset)) {
            fieldTags.get(offset).remove(tag);
        }
    }

    public void addGlobalTag(Attribute tag) {
        globalTags.add(tag);
    }

    public void addReferencedBy(long offset, TypeConstraint other) {
        referencedBy.putIfAbsent(other, new HashSet<>());
        referencedBy.get(other).add(offset);
    }

    public void addReferenceTo(long offset, TypeConstraint other) {
        referenceTo.putIfAbsent(offset, new HashSet<>());
        referenceTo.get(offset).add(other);
    }

    public void removeReferenceTo(long offset, TypeConstraint other) {
        if (referenceTo.containsKey(offset)) {
            referenceTo.get(offset).remove(other);
        }
    }

    public void setTotalSize(long size) {
        this.totalSize.add(size);
        Logging.info(String.format("[Constraint] %s setting total size: %d", shortUUID, size));
    }

    public void setElementSize(long size) {
        this.elementSize.add(size);
        Logging.info(String.format("[Constraint] %s setting element size: %d", shortUUID, size));
    }

    public void merge(TypeConstraint other) {
        // merging fieldMap
        other.fieldMap.forEach((offset, typeMap) -> {
            if (!this.fieldMap.containsKey(offset)) {
                this.fieldMap.put(offset, new HashMap<>(typeMap));
            } else {
                typeMap.forEach((type, count) ->
                        this.fieldMap.get(offset).merge(type, count, Integer::sum));
            }
        });

        // Merging tags
        other.fieldTags.forEach((offset, tagSet) -> {
            this.fieldTags.putIfAbsent(offset, new HashSet<>());
            this.fieldTags.get(offset).addAll(tagSet);
        });

        // Merging globalTags
        this.globalTags.addAll(other.globalTags);

        // Merging ptrLevel
        other.ptrLevel.forEach((offset, level) -> {
            if (this.ptrLevel.containsKey(offset)) {
                this.ptrLevel.put(offset, Math.max(this.ptrLevel.get(offset), level));
            } else {
                this.ptrLevel.put(offset, level);
            }
        });

        // Merging accessOffsets
        other.accessOffsets.forEach((ap, offsets) -> {
            this.accessOffsets.putIfAbsent(ap, new HashSet<>());
            this.accessOffsets.get(ap).addAll(offsets);
        });

        // Handling referenceTo: update new and remove old
        other.referenceTo.forEach((offset, constraints) -> {
            constraints.forEach(constraint -> {
                this.addReferenceTo(offset, constraint);
                constraint.addReferencedBy(offset, this);
            });
        });

        // Handling referencedBy
        other.referencedBy.forEach((constraint, offsets) -> {
            offsets.forEach(offset -> {
                this.addReferencedBy(offset, constraint);
                constraint.removeReferenceTo(offset, other);
                constraint.addReferenceTo(offset,this);
            });
        });

        // Merging size
        this.totalSize.addAll(other.totalSize);
        this.elementSize.addAll(other.elementSize);
    }


    @Override
    public String getName() {
        return shortUUID;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Constraint_" + shortUUID + " {\n");
        if (!totalSize.isEmpty()) {
            sb.append("Possible Total Size: {");
            totalSize.forEach(s -> sb.append("0x").append(Long.toHexString(s)).append(", "));
            sb.append("}\n");
        }

        if (!elementSize.isEmpty()) {
            sb.append("Possible Element Size: {");
            elementSize.forEach(s -> sb.append("0x").append(Long.toHexString(s)).append(", "));
            sb.append("}\n");
        }

        fieldMap.forEach((offset, typeMap) -> {
            sb.append("0x").append(Long.toHexString(offset)).append(" : {");
            typeMap.forEach((type, count) -> sb.append(type.getName()).append(" : ").append(count).append(", "));
            sb.append("}, ");
            if (fieldTags.containsKey(offset)) {
                sb.append("Tags: ");
                fieldTags.get(offset).forEach(tag -> sb.append(tag).append(", "));
            }
            if (ptrLevel.containsKey(offset)) {
                sb.append("PtrLevel: ").append(ptrLevel.get(offset));
            }
            sb.append(", ");
            if (referenceTo.containsKey(offset)) {
                sb.append("ReferenceTo: {");
                referenceTo.get(offset).forEach(ref -> sb.append("Constraint_").append(ref.shortUUID).append(", "));
                sb.append("}");
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

    // In some cases, The FieldTag is not meaningful. For example, if there is a callsite
    // foo(a, b + 1), the b + 1 is a constant, but the fieldTag is MAY_NESTED.
    public boolean isMeaningful() {
        return !fieldMap.isEmpty() || !totalSize.isEmpty() || !elementSize.isEmpty();
    }

    public JsonNode getJsonObj(ObjectMapper mapper) {
        var rootNode = mapper.createObjectNode();
        rootNode.put("TotalSize", totalSize.isEmpty() ? "0x" + Long.toHexString(0) : "0x" + Long.toHexString(totalSize.iterator().next()));
        rootNode.put("ElementSize", elementSize.isEmpty() ? "0x" + Long.toHexString(0) : "0x" + Long.toHexString(elementSize.iterator().next()));

        var globalTagsArray = rootNode.putArray("globalTags");
        globalTags.forEach(tag -> globalTagsArray.add(tag.toString()));

        var referencedByNode = rootNode.putObject("referencedBy");
        referencedBy.forEach((constraint, offsets) -> {
            var offsetArray = referencedByNode.putArray("Constraint_" + constraint.shortUUID);
            offsets.forEach(offset -> offsetArray.add("0x" + Long.toHexString(offset)));
        });

        var fieldsNode = rootNode.putObject("fields");
        fieldMap.forEach((offset, typesMap) -> {
            var offsetNode = fieldsNode.putObject("0x" + Long.toHexString(offset));
            var fieldsArray = offsetNode.putArray("types");
            typesMap.forEach((type, count) -> fieldsArray.add(type.getName() + ": " + count));

            var referenceToArray = offsetNode.putArray("referenceTo");
            referenceTo.getOrDefault(offset, new HashSet<>()).forEach(ref -> referenceToArray.add("Constraint_" + ref.shortUUID));

            offsetNode.put("PtrLevel", ptrLevel.getOrDefault(offset, 0L));

            var tagsArray = offsetNode.putArray("tags");
            fieldTags.getOrDefault(offset, new HashSet<>()).forEach(tag -> tagsArray.add(tag.toString()));
        });

        return rootNode;
    }
}
