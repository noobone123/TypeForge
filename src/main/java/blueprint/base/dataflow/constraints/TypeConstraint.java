package blueprint.base.dataflow.constraints;

import blueprint.base.dataflow.AccessPoints;
import blueprint.base.dataflow.SymbolExpr;
import blueprint.utils.Logging;

import java.util.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class TypeConstraint implements TypeDescriptor {

    public enum Attribute {
        MULTI_ACCESS,
        MAY_NESTED,
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
    public final TreeMap<Long, HashSet<Attribute>> fieldAttrs;
    public final TreeMap<Long, Long> ptrLevel;

    /** The accessOffsets is a map which records the AP and the set of field offsets which are accessed by the AP */
    public final HashMap<AccessPoints.AP, HashSet<Long>> accessOffsets;

    /** This is important, which is used to record the symbol expression which associated with this TypeConstraint */
    public Set<SymbolExpr> associatedExpr;
    public Set<Long> totalSize;
    public Set<Long> elementSize;

    /** The referenceTo is a map from current TypeConstraint's offset to the referenced TypeConstraint */
    public final HashMap<Long, HashSet<TypeConstraint>> referenceTo;
    /** The referencedBy is a map which records which TypeConstraint references the current TypeConstraint and the set of referenced offsets */
    public final HashMap<TypeConstraint, HashSet<Long>> referencedBy;

    public final HashMap<Long, HashSet<TypeConstraint>> nestTo;
    public final HashMap<Long, HashSet<TypeConstraint>> nestedBy;

    public final UUID uuid;
    public final String shortUUID;

    public TypeConstraint() {
        fieldMap = new TreeMap<>();
        fieldAttrs = new TreeMap<>();
        ptrLevel = new TreeMap<>();

        accessOffsets = new HashMap<>();
        uuid = UUID.randomUUID();
        shortUUID = uuid.toString().substring(0, 8);

        referenceTo = new HashMap<>();
        referencedBy = new HashMap<>();

        nestTo = new HashMap<>();
        nestedBy = new HashMap<>();

        associatedExpr = new HashSet<>();
        this.totalSize = new HashSet<>();
        this.elementSize = new HashSet<>();
    }


    public void build() {
        accessOffsets.forEach((ap, offsets) -> {
            if (offsets.size() > 1) {
                for (var offset : offsets) {
                    // If one pcode Access Multiple fields, we should add a tag to the field
                    addFieldAttr(offset, Attribute.MULTI_ACCESS);
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
        Logging.info("TypeConstraint", String.format("Constraint_%s adding field: 0x%x -> %s", shortUUID, offset, type.getName()));
    }

    public void setPtrLevel(long offset, long newLevel) {
        if (ptrLevel.containsKey(offset)) {
            if (ptrLevel.get(offset) < newLevel) {
                ptrLevel.put(offset, newLevel);
                Logging.info("TypeConstraint", String.format("Constraint_%s setting new ptrLevel for 0x%x: %d", shortUUID, offset, newLevel));
            }
        } else {
            ptrLevel.put(offset, newLevel);
            Logging.info("TypeConstraint", String.format("Constraint_%s setting new ptrLevel for 0x%x: %d", shortUUID, offset, newLevel));
        }
    }

    public void addFieldAttr(long offset, Attribute tag) {
        fieldAttrs.putIfAbsent(offset, new HashSet<>());
        fieldAttrs.get(offset).add(tag);
        Logging.info("TypeConstraint", String.format("Constraint_%s adding fieldTag: 0x%x -> %s", shortUUID, offset, tag));
    }

    public void removeFieldTag(long offset, Attribute tag) {
        if (fieldAttrs.containsKey(offset)) {
            fieldAttrs.get(offset).remove(tag);
        }
    }

    public void addReferencedBy(long offset, TypeConstraint other) {
        referencedBy.putIfAbsent(other, new HashSet<>());
        referencedBy.get(other).add(offset);
        Logging.info("TypeConstraint", String.format("Constraint_%s adding referencedBy: 0x%x -> Constraint_%s", shortUUID, offset, other.shortUUID));
    }

    public void addReferenceTo(long offset, TypeConstraint other) {
        referenceTo.putIfAbsent(offset, new HashSet<>());
        referenceTo.get(offset).add(other);
        Logging.info("TypeConstraint", String.format("Constraint_%s adding referenceTo: 0x%x -> Constraint_%s", shortUUID, offset, other.shortUUID));
    }

    public void addNestTo(long offset, TypeConstraint other) {
        nestTo.putIfAbsent(offset, new HashSet<>());
        nestTo.get(offset).add(other);
        Logging.info("TypeConstraint", String.format("Constraint_%s adding nestTo: 0x%x -> Constraint_%s", shortUUID, offset, other.shortUUID));
    }

    public void addNestedBy(long offset, TypeConstraint other) {
        nestedBy.putIfAbsent(offset, new HashSet<>());
        nestedBy.get(offset).add(other);
        Logging.info("TypeConstraint", String.format("Constraint_%s adding nestedBy: 0x%x -> Constraint_%s", shortUUID, offset, other.shortUUID));
    }

    public void setTotalSize(long size) {
        this.totalSize.add(size);
        Logging.info("TypeConstraint", String.format("Constraint_%s setting total size: %d", shortUUID, size));
    }

    public void setElementSize(long size) {
        this.elementSize.add(size);
        Logging.info("TypeConstraint", String.format("Constraint_%s setting element size: %d", shortUUID, size));
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

        // Merging field attributes
        other.fieldAttrs.forEach((offset, tagSet) -> {
            this.fieldAttrs.putIfAbsent(offset, new HashSet<>());
            this.fieldAttrs.get(offset).addAll(tagSet);
        });

        // Merging associatedExpr
        this.associatedExpr.addAll(other.associatedExpr);

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

        mergeXRef(other);

        // Merging size
        this.totalSize.addAll(other.totalSize);
        this.elementSize.addAll(other.elementSize);
    }


    public void mergeXRef(TypeConstraint other) {
        other.referenceTo.forEach((offset, constraints) -> {
            constraints.forEach(constraint -> {
                this.addReferenceTo(offset, constraint);
                constraint.addReferencedBy(offset, this);
            });
        });

        other.referencedBy.forEach((constraint, offsets) -> {
            offsets.forEach(offset -> {
                this.addReferencedBy(offset, constraint);
                constraint.addReferenceTo(offset, this);
            });
        });

        other.nestTo.forEach((offset, constraints) -> {
            constraints.forEach(constraint -> {
                this.addNestTo(offset, constraint);
                constraint.addNestedBy(offset, this);
            });
        });

        other.nestedBy.forEach((offset, constraints) -> {
            constraints.forEach(constraint -> {
                this.addNestedBy(offset, constraint);
                constraint.addNestTo(offset, this);
            });
        });
    }


    public List<Long> collectFieldOffsets() {
        Set<Long> offsets = new HashSet<>(fieldMap.keySet());
        offsets.addAll(fieldAttrs.keySet());
        List<Long> sortedOffset = new ArrayList<>(offsets);
        Collections.sort(sortedOffset);
        return sortedOffset;
    }


    @Override
    public String getName() {
        return shortUUID;
    }

    @Override
    public String toString() {
        return getName();
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

        var exprs = rootNode.putArray("AssociatedExpr");
        associatedExpr.forEach(expr -> exprs.add(expr.toString()));

        rootNode.put("TotalSize", totalSize.isEmpty() ? "0x" + Long.toHexString(0) : "0x" + Long.toHexString(totalSize.iterator().next()));
        rootNode.put("ElementSize", elementSize.isEmpty() ? "0x" + Long.toHexString(0) : "0x" + Long.toHexString(elementSize.iterator().next()));

        var referencedByNode = rootNode.putObject("referencedBy");
        referencedBy.forEach((constraint, offsets) -> {
            var offsetArray = referencedByNode.putArray("Constraint_" + constraint.shortUUID);
            offsets.forEach(offset -> offsetArray.add("0x" + Long.toHexString(offset)));
        });

        var NestedByNode = rootNode.putObject("nestedBy");
        nestedBy.forEach((offset, constraints) -> {
            var constraintArray = NestedByNode.putArray("0x" + Long.toHexString(offset));
            constraints.forEach(constraint -> constraintArray.add("Constraint_" + constraint.shortUUID));
        });

        var fieldsNode = rootNode.putObject("fields");
        List<Long> offsets = collectFieldOffsets();
        offsets.forEach(offset -> {
            var offsetNode = fieldsNode.putObject("0x" + Long.toHexString(offset));

            var fieldsArray = offsetNode.putArray("types");
            fieldMap.getOrDefault(offset, new HashMap<>()).forEach((type, count) -> fieldsArray.add(type.getName() + ": " + count));

            var referenceToArray = offsetNode.putArray("referenceTo");
            referenceTo.getOrDefault(offset, new HashSet<>()).forEach(ref -> referenceToArray.add("Constraint_" + ref.shortUUID));

            var NestToArray = offsetNode.putArray("nestTo");
            nestTo.getOrDefault(offset, new HashSet<>()).forEach(ref -> NestToArray.add("Constraint_" + ref.shortUUID));

            offsetNode.put("PtrLevel", ptrLevel.getOrDefault(offset, 0L));

            var tagsArray = offsetNode.putArray("tags");
            fieldAttrs.getOrDefault(offset, new HashSet<>()).forEach(tag -> tagsArray.add(tag.toString()));
        });

        return rootNode;
    }
}
