package blueprint.base.dataflow.constraints;

import blueprint.base.dataflow.AccessPoints;
import blueprint.base.dataflow.SymbolExpr.SymbolExpr;
import blueprint.base.dataflow.types.TypeDescriptor;
import blueprint.utils.Logging;

import java.util.*;

import blueprint.utils.TCHelper;
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
    public final TreeMap<Long, HashSet<AccessPoints.AP>> fieldAccess;
    public final TreeMap<Long, HashSet<Attribute>> fieldAttrs;
    public final TreeMap<Long, HashSet<SymbolExpr>> fieldExprMap;

    public final HashSet<Attribute> globalAttrs;
    /** The accessOffsets is a map which records the AP and the set of field offsets which are accessed by the AP */
    public final HashMap<AccessPoints.AP, HashSet<Long>> accessOffsets;

    public final Set<TypeDescriptor> polymorphicTypes;

    /** This is important, which is used to record the symbol expression which associated with this TypeConstraint */
    public Set<SymbolExpr> associatedExpr;
    public Set<Long> totalSize;
    public Set<Long> elementSize;

    public Set<TCRelation> relations;

    public TypeConstraint() {
        uuid = UUID.randomUUID();
        shortUUID = uuid.toString().substring(0, 8);

        fieldAccess = new TreeMap<>();
        fieldExprMap = new TreeMap<>();

        fieldAttrs = new TreeMap<>();
        globalAttrs = new HashSet<>();
        accessOffsets = new HashMap<>();
        polymorphicTypes = new HashSet<>();
        associatedExpr = new HashSet<>();
        totalSize = new HashSet<>();
        elementSize = new HashSet<>();

        relations = new HashSet<>();
    }

    public TypeConstraint(TypeConstraint other) {
        this.uuid = UUID.randomUUID();
        this.shortUUID = uuid.toString().substring(0, 8);

        this.fieldAccess = new TreeMap<>();
        for (Map.Entry<Long, HashSet<AccessPoints.AP>> entry : other.fieldAccess.entrySet()) {
            this.fieldAccess.put(entry.getKey(), new HashSet<>(entry.getValue()));
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

        this.associatedExpr = new HashSet<>(other.associatedExpr);

        this.totalSize = new HashSet<>(other.totalSize);

        this.elementSize = new HashSet<>(other.elementSize);

        this.relations = new HashSet<>(other.relations);
    }

    public void addFieldAccess(long offset, AccessPoints.AP ap) {
        // update fieldAccess
        accessOffsets.putIfAbsent(ap, new HashSet<>());
        accessOffsets.get(ap).add(offset);
        fieldAccess.putIfAbsent(offset, new HashSet<>());
        if (fieldAccess.get(offset).add(ap)) {
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

//    public boolean hasReferenceTo(long offset, TypeConstraint other) {
//        return referenceTo.containsKey(offset) && referenceTo.get(offset).contains(other);
//    }
//
//    public void removeReferenceTo(long offset, TypeConstraint other) {
//        if (referenceTo.containsKey(offset)) {
//            referenceTo.get(offset).remove(other);
//            Logging.debug("TypeConstraint", String.format("Constraint_%s removing referenceTo: 0x%x -> Constraint_%s", shortUUID, offset, other.shortUUID));
//
//            if (referenceTo.get(offset).isEmpty()) {
//                referenceTo.remove(offset);
//            }
//        }
//    }
//
//    public void removeReferencedBy(TypeConstraint other, long offset) {
//        if (referencedBy.containsKey(other)) {
//            referencedBy.get(other).remove(offset);
//            Logging.debug("TypeConstraint", String.format("Constraint_%s removing referencedBy: Constraint_%s -> 0x%x", shortUUID, other.shortUUID, offset));
//
//            if (referencedBy.get(other).isEmpty()) {
//                referencedBy.remove(other);
//            }
//        }
//    }
//
//    public void addNestTo(long offset, TypeConstraint other) {
//        nestTo.putIfAbsent(offset, new HashSet<>());
//        nestTo.get(offset).add(other);
//        Logging.debug("TypeConstraint", String.format("Constraint_%s adding nestTo: 0x%x -> Constraint_%s", shortUUID, offset, other.shortUUID));
//    }
//
//    public void addNestedBy(TypeConstraint other, long offset) {
//        nestedBy.putIfAbsent(other, new HashSet<>());
//        nestedBy.get(other).add(offset);
//        Logging.debug("TypeConstraint", String.format("Constraint_%s adding nestedBy: Constraint_%s -> 0x%x", shortUUID, other.shortUUID, offset));
//    }
//
//    public void removeNestTo(long offset, TypeConstraint other) {
//        if (nestTo.containsKey(offset)) {
//            nestTo.get(offset).remove(other);
//            Logging.debug("TypeConstraint", String.format("Constraint_%s removing nestTo: 0x%x -> Constraint_%s", shortUUID, offset, other.shortUUID));
//
//            if (nestTo.get(offset).isEmpty()) {
//                nestTo.remove(offset);
//            }
//        }
//    }
//
//    public void removeNestedBy(TypeConstraint other, long offset) {
//        if (nestedBy.containsKey(other)) {
//            nestedBy.get(other).remove(offset);
//            Logging.debug("TypeConstraint", String.format("Constraint_%s removing nestedBy: Constraint_%s -> 0x%x", shortUUID, other.shortUUID, offset));
//
//            if (nestedBy.get(other).isEmpty()) {
//                nestedBy.remove(other);
//            }
//        }
//    }

    public void setTotalSize(long size) {
        this.totalSize.add(size);
        Logging.info("TypeConstraint", String.format("Constraint_%s setting total size: %d", shortUUID, size));
    }

    public void setElementSize(long size) {
        this.elementSize.add(size);
        Logging.info("TypeConstraint", String.format("Constraint_%s setting element size: %d", shortUUID, size));
    }

    public void addAssociatedExpr(SymbolExpr expr) {
        if (associatedExpr.add(expr)) {
            Logging.info("TypeConstraint", String.format("Constraint_%s adding associatedExpr: %s", shortUUID, expr.toString()));
        }
    }

//    public void mergeXRef(TypeConstraint other) {
//        // Be careful with Recursive Reference or Recursive Nest
//        List<Runnable> changes = new ArrayList<>();
//        other.referenceTo.forEach((offset, constraints) -> {
//            constraints.forEach(refee -> {
//                if (refee != other) {
//                    changes.add(() -> {
//                        this.addReferenceTo(offset, refee);
//                        refee.addReferencedBy(this, offset);
//                        other.removeReferenceTo(offset, refee);
//                        refee.removeReferencedBy(other, offset);
//                    });
//                }
//                // Recursive Reference to
//                else {
//                    changes.add(() -> {
//                        this.addReferenceTo(offset, this);
//                        this.addReferencedBy(this, offset);
//                        other.removeReferenceTo(offset, refee);
//                        refee.removeReferencedBy(other, offset);
//                    });
//                }
//            });
//        });
//
//        other.referencedBy.forEach((refer, offsets) -> {
//            if (refer != other) {
//                offsets.forEach(offset -> {
//                    changes.add(() -> {
//                        this.addReferencedBy(refer, offset);
//                        refer.addReferenceTo(offset, this);
//                        other.removeReferencedBy(refer, offset);
//                        refer.removeReferenceTo(offset, other);
//                    });
//                });
//            }
//            // Recursive Reference by
//            else {
//                offsets.forEach(offset -> {
//                    changes.add(() -> {
//                        this.addReferencedBy(this, offset);
//                        this.addReferenceTo(offset, this);
//                        other.removeReferencedBy(refer, offset);
//                        refer.removeReferenceTo(offset, other);
//                    });
//                });
//            }
//        });
//
//        other.nestTo.forEach((offset, constraints) -> {
//            constraints.forEach(nestee -> {
//                if (nestee != other) {
//                    changes.add(() -> {
//                        this.addNestTo(offset, nestee);
//                        nestee.addNestedBy(this, offset);
//                        other.removeNestTo(offset, nestee);
//                        nestee.removeNestedBy(other, offset);
//                    });
//                }
//                // Recursive Nest to
//                else {
//                    changes.add(() -> {
//                        this.addNestTo(offset, this);
//                        this.addNestedBy(this, offset);
//                        other.removeNestTo(offset, nestee);
//                        nestee.removeNestedBy(other, offset);
//                    });
//                }
//            });
//        });
//
//        other.nestedBy.forEach((nester, offsets) -> {
//            if (nester != other) {
//                offsets.forEach(offset -> {
//                    changes.add(() -> {
//                        this.addNestedBy(nester, offset);
//                        nester.addNestTo(offset, this);
//                        other.removeNestedBy(nester, offset);
//                        nester.removeNestTo(offset, other);
//                    });
//                });
//            }
//            // Recursive Nested by
//            else {
//                offsets.forEach(offset -> {
//                    changes.add(() -> {
//                        this.addNestedBy(this, offset);
//                        this.addNestTo(offset, this);
//                        other.removeNestedBy(nester, offset);
//                        nester.removeNestTo(offset, other);
//                    });
//                });
//            }
//        });
//
//        changes.forEach(Runnable::run);
//    }

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
//    public static void remove(TypeConstraint constraint) {
//        constraint.referenceTo.forEach((offset, constraints) -> {
//            constraints.forEach(refee -> refee.removeReferencedBy(constraint, offset));
//        });
//
//        constraint.referencedBy.forEach((refer, offsets) -> {
//            offsets.forEach(offset -> refer.removeReferenceTo(offset, constraint));
//        });
//
//        constraint.nestTo.forEach((offset, constraints) -> {
//            constraints.forEach(nestee -> nestee.removeNestedBy(constraint, offset));
//        });
//
//        constraint.nestedBy.forEach((nester, offsets) -> {
//            offsets.forEach(offset -> nester.removeNestTo(offset, constraint));
//        });
//    }


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
            this.fieldAccess.putIfAbsent(offset, new HashSet<>());
            this.fieldAccess.get(offset).addAll(aps);
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

        // Merging associatedExpr
        this.associatedExpr.addAll(other.associatedExpr);

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

    /**
     * This function is used to check whether current TypeConstraint is related to Composite DataType
     * For detailed information, we determine by:
     * 1. Whether constraints maybe a Structure, Array or Union
     * 2. Whether constraints maybe a Pointer which points to a Structure, Array or Union
     * @return if the TypeConstraint is related to Composite DataType
     */
    public boolean isInterested() {
        if (!getPolymorphicTypes().isEmpty()) {
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

    public boolean isEmpty() {
        return fieldAccess.isEmpty() && fieldAttrs.isEmpty() && polymorphicTypes.isEmpty() && totalSize.isEmpty() && elementSize.isEmpty();
    }

    public void addPolymorphicType(TypeDescriptor type) {
        polymorphicTypes.add(type);
        Logging.info("TypeConstraint", String.format("Constraint_%s adding polymorphicType: %s", shortUUID, type.getName()));
    }

    public Set<TypeDescriptor> getPolymorphicTypes() {
        return polymorphicTypes;
    }

    /** Dump current TypeConstraint's layout */
    public String dumpLayout() {
        StringBuilder sb = new StringBuilder();
        sb.append("Constraint_").append(shortUUID).append(":\n");
        sb.append("PolyTypes: ").append(polymorphicTypes).append("\n");
        fieldAccess.forEach((offset, aps) -> {
            sb.append("\t");
            sb.append(String.format("0x%x: ", offset));
            sb.append("\t");
            aps.forEach(ap -> sb.append(ap.dataType.getName()).append(", "));
            sb.append("\n");
        });
        return sb.toString();
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

        // dump all totalSize and elementSize
        var sizeNode = rootNode.putArray("TotalSize");
        totalSize.forEach(size -> sizeNode.add("0x" + Long.toHexString(size)));
        var elementSizeNode = rootNode.putArray("ElementSize");
        elementSize.forEach(size -> elementSizeNode.add("0x" + Long.toHexString(size)));
        rootNode.put("GlobalAttrs", globalAttrs.toString());


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

            var tagsArray = offsetNode.putArray("Attrs");
            fieldAttrs.getOrDefault(offset, new HashSet<>()).forEach(tag -> tagsArray.add(tag.toString()));

            var exprsArray = offsetNode.putArray("Exprs");
            fieldExprMap.getOrDefault(offset, new HashSet<>()).forEach(expr -> exprsArray.add(expr.toString()));
        });

        // dump polymorphicTypes
        var polymorphicTypesNode = rootNode.putArray("PolymorphicTypes");
        polymorphicTypes.forEach(type -> polymorphicTypesNode.add(type.getName()));

        return rootNode;
    }
}
