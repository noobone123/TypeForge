package blueprint.base.dataflow.constraints;

import blueprint.base.dataflow.AccessPoints;
import blueprint.base.dataflow.SymbolExpr;
import blueprint.utils.Logging;

import java.util.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;

public class TypeConstraint implements TypeDescriptor {

    public enum Attribute {
        SAME_ACCESS_ON_MULTI_OFFSETS,
        MAY_NESTED,
        MAY_ARRAY_PTR
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
    public final TreeMap<Long, HashSet<AccessPoints.AP>> fieldAccess;
    /** The fieldMap should be built by the fieldAccess after merging */
    public final TreeMap<Long, TypeDescriptor> fieldMap;
    public final TreeMap<Long, HashSet<Attribute>> fieldAttrs;
    public final HashSet<Attribute> globalAttrs;
    public final TreeMap<Long, Long> fieldPtrLevel;
    /** The accessOffsets is a map which records the AP and the set of field offsets which are accessed by the AP */
    public final HashMap<AccessPoints.AP, HashSet<Long>> accessOffsets;

    /** decompiler inference info */
    public boolean isDecompilerCompositeType = false;
    public DataType decompilerDataType;
    public String decompilerDataTypeName;

    /** This is important, which is used to record the symbol expression which associated with this TypeConstraint */
    public Set<SymbolExpr> associatedExpr;
    public Set<Long> totalSize;
    public Set<Long> elementSize;
    public TypeDescriptor elementType;

    /** The referenceTo is a map from current TypeConstraint's offset to the referenced TypeConstraint */
    public HashMap<Long, HashSet<TypeConstraint>> referenceTo;
    /** The referencedBy is a map which records which TypeConstraint references the current TypeConstraint and the set of referenced offsets */
    public final HashMap<TypeConstraint, HashSet<Long>> referencedBy;

    public final HashMap<Long, HashSet<TypeConstraint>> nestTo;
    public final HashMap<TypeConstraint, HashSet<Long>> nestedBy;

    public final UUID uuid;
    public final String shortUUID;

    public TypeConstraint() {
        fieldAccess = new TreeMap<>();
        fieldMap = new TreeMap<>();
        fieldAttrs = new TreeMap<>();
        globalAttrs = new HashSet<>();
        fieldPtrLevel = new TreeMap<>();

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

    public void addFieldAccess(long offset, AccessPoints.AP ap) {
        accessOffsets.putIfAbsent(ap, new HashSet<>());
        accessOffsets.get(ap).add(offset);
        fieldAccess.putIfAbsent(offset, new HashSet<>());
        if (fieldAccess.get(offset).add(ap)) {
            fieldAccess.get(offset).add(ap);
            Logging.info("TypeConstraint", String.format("Constraint_%s adding field: 0x%x -> %s", shortUUID, offset, ap.dataType));
        }
    }

    public void addField(long offset, TypeDescriptor type) {
        fieldMap.put(offset, type);
        Logging.info("TypeConstraint", String.format("Constraint_%s adding field: 0x%x -> %s", shortUUID, offset, type.getName()));
    }

    public void setPtrLevel(long offset, long newLevel) {
        if (fieldPtrLevel.containsKey(offset)) {
            if (fieldPtrLevel.get(offset) < newLevel) {
                fieldPtrLevel.put(offset, newLevel);
                Logging.info("TypeConstraint", String.format("Constraint_%s setting new ptrLevel for 0x%x: %d", shortUUID, offset, newLevel));
            }
        } else {
            fieldPtrLevel.put(offset, newLevel);
            Logging.info("TypeConstraint", String.format("Constraint_%s setting new ptrLevel for 0x%x: %d", shortUUID, offset, newLevel));
        }
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

    public void addReferenceTo(long offset, TypeConstraint other) {
        referenceTo.putIfAbsent(offset, new HashSet<>());
        referenceTo.get(offset).add(other);
        Logging.debug("TypeConstraint", String.format("Constraint_%s adding referenceTo: 0x%x -> Constraint_%s", shortUUID, offset, other.shortUUID));
    }

    public void addReferencedBy(TypeConstraint other, long offset) {
        referencedBy.putIfAbsent(other, new HashSet<>());
        referencedBy.get(other).add(offset);
        Logging.debug("TypeConstraint", String.format("Constraint_%s adding referencedBy: Constraint_%s -> 0x%x", shortUUID, other.shortUUID, offset));
    }

    public void removeReferenceTo(long offset, TypeConstraint other) {
        if (referenceTo.containsKey(offset)) {
            referenceTo.get(offset).remove(other);
            Logging.debug("TypeConstraint", String.format("Constraint_%s removing referenceTo: 0x%x -> Constraint_%s", shortUUID, offset, other.shortUUID));

            if (referenceTo.get(offset).isEmpty()) {
                referenceTo.remove(offset);
            }
        }
    }

    public void removeReferencedBy(TypeConstraint other, long offset) {
        if (referencedBy.containsKey(other)) {
            referencedBy.get(other).remove(offset);
            Logging.debug("TypeConstraint", String.format("Constraint_%s removing referencedBy: Constraint_%s -> 0x%x", shortUUID, other.shortUUID, offset));

            if (referencedBy.get(other).isEmpty()) {
                referencedBy.remove(other);
            }
        }
    }

    public void addNestTo(long offset, TypeConstraint other) {
        nestTo.putIfAbsent(offset, new HashSet<>());
        nestTo.get(offset).add(other);
        Logging.debug("TypeConstraint", String.format("Constraint_%s adding nestTo: 0x%x -> Constraint_%s", shortUUID, offset, other.shortUUID));
    }

    public void addNestedBy(TypeConstraint other, long offset) {
        nestedBy.putIfAbsent(other, new HashSet<>());
        nestedBy.get(other).add(offset);
        Logging.debug("TypeConstraint", String.format("Constraint_%s adding nestedBy: Constraint_%s -> 0x%x", shortUUID, other.shortUUID, offset));
    }

    public void removeNestTo(long offset, TypeConstraint other) {
        if (nestTo.containsKey(offset)) {
            nestTo.get(offset).remove(other);
            Logging.debug("TypeConstraint", String.format("Constraint_%s removing nestTo: 0x%x -> Constraint_%s", shortUUID, offset, other.shortUUID));

            if (nestTo.get(offset).isEmpty()) {
                nestTo.remove(offset);
            }
        }
    }

    public void removeNestedBy(TypeConstraint other, long offset) {
        if (nestedBy.containsKey(other)) {
            nestedBy.get(other).remove(offset);
            Logging.debug("TypeConstraint", String.format("Constraint_%s removing nestedBy: Constraint_%s -> 0x%x", shortUUID, other.shortUUID, offset));

            if (nestedBy.get(other).isEmpty()) {
                nestedBy.remove(other);
            }
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

    public void setElementType(TypeConstraint type) {
        this.elementType = type;
        Logging.info("TypeConstraint", String.format("Constraint_%s setting element type: %s", shortUUID, type.shortUUID));
    }

    public void addAssociatedExpr(SymbolExpr expr) {
        if (associatedExpr.add(expr)) {
            Logging.info("TypeConstraint", String.format("Constraint_%s adding associatedExpr: %s", shortUUID, expr.toString()));
        }
    }

    public Set<SymbolExpr> getAssociatedExpr() {
        return associatedExpr;
    }

    public void merge(TypeConstraint other) {
        if (other == null) {
            return;
        }

        // merging fieldAccess
        other.fieldAccess.forEach((offset, aps) -> {
            this.fieldAccess.putIfAbsent(offset, new HashSet<>());
            this.fieldAccess.get(offset).addAll(aps);
        });

        // Merging field attributes
        other.fieldAttrs.forEach((offset, tagSet) -> {
            this.fieldAttrs.putIfAbsent(offset, new HashSet<>());
            this.fieldAttrs.get(offset).addAll(tagSet);
        });

        // Merging global attributes
        this.globalAttrs.addAll(other.globalAttrs);

        // Merging associatedExpr
        this.associatedExpr.addAll(other.associatedExpr);

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
        // Be careful with Recursive Reference or Recursive Nest
        List<Runnable> changes = new ArrayList<>();
        other.referenceTo.forEach((offset, constraints) -> {
            constraints.forEach(refee -> {
                if (refee != other) {
                    changes.add(() -> {
                        this.addReferenceTo(offset, refee);
                        refee.addReferencedBy(this, offset);
                        other.removeReferenceTo(offset, refee);
                        refee.removeReferencedBy(other, offset);
                    });
                }
                // Recursive Reference to
                else {
                    changes.add(() -> {
                        this.addReferenceTo(offset, this);
                        this.addReferencedBy(this, offset);
                        other.removeReferenceTo(offset, refee);
                        refee.removeReferencedBy(other, offset);
                    });
                }
            });
        });

        other.referencedBy.forEach((refer, offsets) -> {
            if (refer != other) {
                offsets.forEach(offset -> {
                    changes.add(() -> {
                        this.addReferencedBy(refer, offset);
                        refer.addReferenceTo(offset, this);
                        other.removeReferencedBy(refer, offset);
                        refer.removeReferenceTo(offset, other);
                    });
                });
            }
            // Recursive Reference by
            else {
                offsets.forEach(offset -> {
                    changes.add(() -> {
                        this.addReferencedBy(this, offset);
                        this.addReferenceTo(offset, this);
                        other.removeReferencedBy(refer, offset);
                        refer.removeReferenceTo(offset, other);
                    });
                });
            }
        });

        other.nestTo.forEach((offset, constraints) -> {
            constraints.forEach(nestee -> {
                if (nestee != other) {
                    changes.add(() -> {
                        this.addNestTo(offset, nestee);
                        nestee.addNestedBy(this, offset);
                        other.removeNestTo(offset, nestee);
                        nestee.removeNestedBy(other, offset);
                    });
                }
                // Recursive Nest to
                else {
                    changes.add(() -> {
                        this.addNestTo(offset, this);
                        this.addNestedBy(this, offset);
                        other.removeNestTo(offset, nestee);
                        nestee.removeNestedBy(other, offset);
                    });
                }
            });
        });

        other.nestedBy.forEach((nester, offsets) -> {
            if (nester != other) {
                offsets.forEach(offset -> {
                    changes.add(() -> {
                        this.addNestedBy(nester, offset);
                        nester.addNestTo(offset, this);
                        other.removeNestedBy(nester, offset);
                        nester.removeNestTo(offset, other);
                    });
                });
            }
            // Recursive Nested by
            else {
                offsets.forEach(offset -> {
                    changes.add(() -> {
                        this.addNestedBy(this, offset);
                        this.addNestTo(offset, this);
                        other.removeNestedBy(nester, offset);
                        nester.removeNestTo(offset, other);
                    });
                });
            }
        });

        changes.forEach(Runnable::run);
    }

    public List<Long> collectFieldOffsets() {
        Set<Long> offsets = new HashSet<>(fieldAccess.keySet());
        offsets.addAll(fieldAttrs.keySet());
        List<Long> sortedOffset = new ArrayList<>(offsets);
        Collections.sort(sortedOffset);
        return sortedOffset;
    }

    /**
     * Remove current constraint, which means remove all reference and nest edges
     * @param constraint the constraint to be removed
     */
    public static void remove(TypeConstraint constraint) {
        constraint.referenceTo.forEach((offset, constraints) -> {
            constraints.forEach(refee -> refee.removeReferencedBy(constraint, offset));
        });

        constraint.referencedBy.forEach((refer, offsets) -> {
            offsets.forEach(offset -> refer.removeReferenceTo(offset, constraint));
        });

        constraint.nestTo.forEach((offset, constraints) -> {
            constraints.forEach(nestee -> nestee.removeNestedBy(constraint, offset));
        });

        constraint.nestedBy.forEach((nester, offsets) -> {
            offsets.forEach(offset -> nester.removeNestTo(offset, constraint));
        });
    }

    /**
     * Check whether the current TypeConstraint overlaps with another TypeConstraint.
     * Overlap means this fields' layout is not compatible with the other fields' layout.
     *
     * @param other The TypeConstraint to check against.
     * @return true if there is an overlap, false otherwise.
     */
    public boolean checkFieldConflict(TypeConstraint other) {

        class Interval {
            final long start;
            final long end;

            Interval(long start, long end) {
                this.start = start;
                this.end = end;
            }

            @Override
            public boolean equals(Object obj) {
                if (obj instanceof Interval) {
                    return this.start == ((Interval) obj).start && this.end == ((Interval) obj).end;
                }
                return false;
            }

            @Override
            public int hashCode() {
                return Objects.hash(start, end);
            }
        }

        if (this == other) {
            return false;
        }

        Set<Interval> thisIntervals = new HashSet<>();
        for (var offset : this.fieldAccess.keySet()) {
            long endOffset = this.calcFieldEndOffset(offset);
            thisIntervals.add(new Interval(offset, endOffset));
        }

        Set<Interval> otherIntervals = new HashSet<>();
        for (var offset : other.fieldAccess.keySet()) {
            long endOffset = other.calcFieldEndOffset(offset);
            otherIntervals.add(new Interval(offset, endOffset));
        }

        Set<Interval> commonIntervals = new HashSet<>(thisIntervals);
        commonIntervals.retainAll(otherIntervals);

        thisIntervals.removeAll(commonIntervals);
        otherIntervals.removeAll(commonIntervals);

        if (thisIntervals.isEmpty() || otherIntervals.isEmpty()) {
            return false;
        }

        List<Interval> mergedIntervals = new ArrayList<>(thisIntervals);
        mergedIntervals.addAll(otherIntervals);
        mergedIntervals.sort(Comparator.comparingLong(interval -> interval.start));
        for (int i = 0; i < mergedIntervals.size() - 1; i++) {
            Interval current = mergedIntervals.get(i);
            Interval next = mergedIntervals.get(i + 1);
            if (current.end > next.start) {
                return true;
            }
        }

        return false;
    }

    public Long calcFieldEndOffset(Long offset) {
        Long endOffset = offset;
        var fields = fieldAccess.get(offset);
        if (fields == null) {
            return endOffset;
        }

        for (var ap : fields) {
            if (ap.dataType != null) {
                endOffset = Math.max(endOffset, offset + ((PrimitiveTypeDescriptor)ap.dataType).getDataTypeSize());
            }
        }
        return endOffset;
    }


    @Override
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

    /**
     * This function is used to check whether current TypeConstraint is related to Composite DataType
     * For detailed information, we determine by:
     * 1. Whether constraints maybe a Structure, Array or Union
     * 2. Whether constraints maybe a Pointer which points to a Structure, Array or Union
     * @return if the TypeConstraint is related to Composite DataType
     */
    public boolean isInterested() {
        if (isDecompilerCompositeType) {
            return true;
        }

        for (var aps : fieldAccess.values()) {
            for (AccessPoints.AP ap : aps) {
                if (ap.dataType != null) {
                    return true;
                }
            }
        }
        return !totalSize.isEmpty() || !elementSize.isEmpty();
    }

    public JsonNode getJsonObj(ObjectMapper mapper) {
        var rootNode = mapper.createObjectNode();

        // Add associatedExpr and it's attributes
        var exprs = rootNode.putArray("AssociatedExpr");
        associatedExpr.forEach(expr -> {
            var exprNode = exprs.addObject();
            exprNode.put("Expr", expr.toString());
            exprNode.put("Attributes", expr.getAttributes().toString());
            exprNode.put("Size", "0x" + Long.toHexString(expr.variableSize));
        });

        rootNode.put("TotalSize", totalSize.isEmpty() ? "0x" + Long.toHexString(0) : "0x" + Long.toHexString(totalSize.iterator().next()));
        rootNode.put("ElementSize", elementSize.isEmpty() ? "0x" + Long.toHexString(0) : "0x" + Long.toHexString(elementSize.iterator().next()));
        rootNode.put("GlobalAttrs", globalAttrs.toString());

        var referencedByNode = rootNode.putObject("referencedBy");
        referencedBy.forEach((constraint, offsets) -> {
            var offsetArray = referencedByNode.putArray("Constraint_" + constraint.shortUUID);
            offsets.forEach(offset -> offsetArray.add("0x" + Long.toHexString(offset)));
        });

        var NestedByNode = rootNode.putObject("nestedBy");
        nestedBy.forEach((constraint, offsets) -> {
            var offsetArray = NestedByNode.putArray("Constraint_" + constraint.shortUUID);
            offsets.forEach(offset -> offsetArray.add("0x" + Long.toHexString(offset)));
        });

        var fieldsNode = rootNode.putObject("fields");
        List<Long> offsets = collectFieldOffsets();
        offsets.forEach(offset -> {
            var offsetNode = fieldsNode.putObject("0x" + Long.toHexString(offset));

            var fieldsArray = offsetNode.putArray("types");
            fieldAccess.getOrDefault(offset, new HashSet<>()).forEach(ap -> {
                if (ap.dataType != null) {
                    fieldsArray.add(ap.dataType.getName());
                }
            });

            var referenceToArray = offsetNode.putArray("referenceTo");
            referenceTo.getOrDefault(offset, new HashSet<>()).forEach(ref -> referenceToArray.add("Constraint_" + ref.shortUUID));

            var NestToArray = offsetNode.putArray("nestTo");
            nestTo.getOrDefault(offset, new HashSet<>()).forEach(ref -> NestToArray.add("Constraint_" + ref.shortUUID));

            offsetNode.put("PtrLevel", fieldPtrLevel.getOrDefault(offset, 0L));

            var tagsArray = offsetNode.putArray("Attrs");
            fieldAttrs.getOrDefault(offset, new HashSet<>()).forEach(tag -> tagsArray.add(tag.toString()));
        });

        return rootNode;
    }

    /**
     * update a TypeConstraint by the given Structure's DataType
     */
    public void updateTypeConstraintByCompositeDataType(DataType DT) {
        if (DT instanceof Structure structDT) {
            decompilerDataTypeName = structDT.getName();
            decompilerDataType = structDT;
            isDecompilerCompositeType = true;
            setTotalSize(structDT.getLength());
            for (var field: structDT.getComponents()) {
                addField(field.getOffset(), new PrimitiveTypeDescriptor(field.getDataType()));
            }
        }
    }


    public void updateTypeConstraintByArrayDataType(DataType DT) {
        if (DT instanceof Array arrayDT) {
            setTotalSize(arrayDT.getLength());
            setElementSize(arrayDT.getElementLength());
            var elementDT = arrayDT.getDataType();
            if (elementDT instanceof Structure structDT) {
                elementType = new TypeConstraint();
                ((TypeConstraint) elementType).updateTypeConstraintByCompositeDataType(structDT);
            } else {
                elementType = new PrimitiveTypeDescriptor(elementDT);
            }
        }
    }
}
