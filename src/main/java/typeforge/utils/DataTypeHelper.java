package typeforge.utils;

import typeforge.base.dataflow.AccessPoints;
import typeforge.base.dataflow.constraint.Skeleton;
import typeforge.base.passes.Window;
import ghidra.program.model.data.*;

import java.util.*;

public class DataTypeHelper {

    private static final DataTypeManager dtM = Global.currentProgram.getDataTypeManager();
    private static final Map<String, DataType> nameToDTMap = new HashMap<>();
    private static final String DEFAULT_STRUCT_BASENAME = "ClayStruct";
    private static final String DEFAULT_ANON_STRUCT_BASENAME = "ClayAnonStruct";
    private static final String DEFAULT_UNION_BASENAME = "ClayUnion";
    private static final String DEFAULT_ANON_UNION_BASENAME = "ClayAnonUnion";
    private static final String DEFAULT_CATEGORY = "/TypeClay_structs";


    public static void prepare() {
        for (var iter = dtM.getAllDataTypes(); iter.hasNext(); ) {
            var dt = iter.next();
            nameToDTMap.put(dt.getName(), dt);
        }
    }

    public static DataType getDataTypeByName(String name) {
        var result = nameToDTMap.get(name);
        if (result == null) {
            Logging.warn("DataTypeHelper", "DataType not found: " + name);
            return null;
        } else {
            return result;
        }
    }

    public static DataType getPointerDT(DataType dt, int ptrLevel) {
        if (ptrLevel == 0) {
            return dt;
        }
        DataType result = dt;
        while (ptrLevel > 0) {
            result = dtM.getPointer(result);
            if (result == null) {
                Logging.warn("DataTypeHelper", "Pointer data type not found: " + dt.getName());
                return null;
            }
            ptrLevel--;
        }

        return result;
    }

    public static int calculateLayoutHash(Structure structure) {
        int hash = 1;
        for (var component: structure.getComponents()) {
            int fieldHash = component.getDataType().getLength();
            fieldHash = 31 * fieldHash + component.getOrdinal();
            fieldHash = 31 * fieldHash + component.getOffset();
            fieldHash = 31 * fieldHash + component.getLength();
            hash = 31 * hash + fieldHash;
        }
        return hash;
    }

    /**
     * Check if the data type is a complex type or a pointer pointing to a complex type.
     * Complex type includes structure, union, array, etc.
     * @param dt the data type
     * @return true/false
     */
    public static boolean isComplexType(DataType dt) {
        if (dt instanceof Pointer pointer) {
            return isComplexType(pointer.getDataType());

        } else if (dt instanceof TypeDef typedef) {
            return isComplexType(typedef.getBaseDataType());

        } else {
            return dt instanceof Composite || dt instanceof Array;
        }
    }

    /**
     * If the data type is a pointer, typedef or array, we should get the base data type.
     * If the data type is a composite, we should return itself.
     * @param dt the data type
     * @return the base data type
     */
    public static DataType getBaseDataType(DataType dt) {
        if (dt instanceof Composite composite) {
            return composite;
        } else if (dt instanceof Array array) {
            return getBaseDataType(array.getDataType());
        } else if (dt instanceof Pointer pointer) {
            return getBaseDataType(pointer.getDataType());
        } else if (dt instanceof TypeDef typedef) {
            return getBaseDataType(typedef.getBaseDataType());
        } else {
            Logging.warn("DataTypeHelper", "Unexpected data type: " + dt.getName());
            return dt;
        }
    }

    public static Structure createAnonStructureFromWindow(Window window) {
        Logging.info("Generator", "Creating Anon Structure Type with Length: 0x" + Integer.toHexString(window.getAlignedWindowSize()));
        String structName = dtM.getUniqueName(new CategoryPath(DEFAULT_CATEGORY), DEFAULT_ANON_STRUCT_BASENAME);
        var structDT = new StructureDataType(new CategoryPath(DEFAULT_CATEGORY), structName, window.getAlignedWindowSize(), dtM);
        var winElements = window.getWindowElements();
        var ptrLevel = window.getPtrLevel();
        for (var entry: winElements.entrySet()) {
            var offset = entry.getKey();
            var element = entry.getValue();
            DataType dt;
            String name;
            String comment = null;
            if (element instanceof Skeleton skt) {
                dt = getPointerDT(DataTypeHelper.getDataTypeByName("void"), ptrLevel.get(offset));
                name = String.format("ref_0x%s_%s", Long.toHexString(offset), skt.toString());
            } else {
                dt = ((AccessPoints.APSet) element).mostAccessedDT;
                name = String.format("field_0x%s", Long.toHexString(offset));
            }
            structDT.replaceAtOffset(offset, dt, dt.getLength(), name, comment);
        }
        return structDT;
    }

    /**
     * Create a new structure
     * @return the new Structure
     */
    public static Structure createUniqueStructure(Skeleton skt, Map<Integer, DataType> componentMap) {
        Logging.info("Generator", "Creating Structure Type with Length: 0x" + Integer.toHexString(skt.getSize()));
        String structName = dtM.getUniqueName(new CategoryPath(DEFAULT_CATEGORY), DEFAULT_STRUCT_BASENAME);
        var structDT = new StructureDataType(new CategoryPath(DEFAULT_CATEGORY), structName, skt.getSize(), dtM);
        populateStructure(structDT, componentMap, skt);
        return structDT;
    }


    public static Union createAnonUnion(Skeleton skt, Long offset) {
        Logging.info("Generator", "Creating Union Type");
        String unionName = dtM.getUniqueName(new CategoryPath(DEFAULT_CATEGORY), DEFAULT_ANON_UNION_BASENAME);
        var unionDT = new UnionDataType(new CategoryPath(DEFAULT_CATEGORY), unionName, dtM);
        int index = 0;

        for (var dt: skt.finalConstraint.fieldAccess.get(offset).allDTs) {
            var name = String.format("union_member_%d", index);
            unionDT.add(dt, dt.getLength(), name, null);
            index++;
        }

        if (skt.finalPtrReference.containsKey(offset)) {
            var name = String.format("union_member_%s", skt.finalPtrReference.get(offset).toString());
            var dt = DataTypeHelper.getPointerDT(DataTypeHelper.getDataTypeByName("void"),
                    skt.ptrLevel.get(offset));
            unionDT.add(dt, Global.currentProgram.getDefaultPointerSize(), name, null);
        }

        return unionDT;
    }

    public static Array createArray(DataType elementDT, int length) {
        Logging.info("Generator", String.format("Creating Array Type of %s with Length: %d", elementDT.getName(), length));
        return new ArrayDataType(elementDT, length, elementDT.getLength(), dtM);
    }

    public static void populateStructure(Structure structDT, Map<Integer, DataType> componentMap, Skeleton skt) {
        for (var entry: componentMap.entrySet()) {
            var offset = entry.getKey();
            var dt = entry.getValue();

            if (structDT.getLength() < (offset + dt.getLength())) {
                skt.dumpInfo();
                Logging.error("Generator", String.format("Offset + DT Length (0x%x + 0x%x) > Structure Length (0x%x)",
                        offset, dt.getLength(), structDT.getLength()));
                return;
            }

            try {
                String name = null;
                String comment = null;
                if (skt.finalPtrReference.containsKey((long) offset)) {
                    name = String.format("ref_0x%s_%s", Long.toHexString(offset), skt.finalPtrReference.get((long) offset).toString());
                }
                else if (dt instanceof Array) {
                    name = String.format("array_field_0x%s", Long.toHexString(offset));
                }
                else {
                    name = String.format("field_0x%s", Long.toHexString(offset));
                }
                structDT.replaceAtOffset(offset, dt, dt.getLength(), name, comment);
            }
            catch (IllegalArgumentException e) {
                Logging.error("Generator", "Failed to populate structure");
                return;
            }
        }
        dtM.addDataType(structDT, DataTypeConflictHandler.DEFAULT_HANDLER);
    }

    public static int getStructDTHash(Structure structDT) {
        int hash = 1;
        for (var component: structDT.getComponents()) {
            int fieldHash = component.getDataType().hashCode();
            fieldHash = 31 * fieldHash + component.getOrdinal();
            fieldHash = 31 * fieldHash + component.getOffset();

            hash = 31 * hash + fieldHash;
        }
        return hash;
    }

    public static DataType getPointerOfStruct(Structure structDT) {
        DataType pointerDT = new PointerDataType(structDT);
        dtM.addDataType(pointerDT, DataTypeConflictHandler.DEFAULT_HANDLER);
        return pointerDT;
    }

    public static DataType getDataTypeInSize(int size) {
        switch (size) {
            case 1:
                return getDataTypeByName("byte");
            case 2:
                return getDataTypeByName("word");
            case 4:
                return getDataTypeByName("dword");
            case 8:
                return getDataTypeByName("qword");
            default:
                return getDataTypeByName("undefined");
        }
    }


    /**
     * Traverse the category and get all data types in the category.
     * @param result the set to store the result
     * @param category the category to traverse
     */
    private static void traverseTypeCategory(Set<DataType> result, Category category) {
        List<Category> workList = new LinkedList<>();
        Set<Category> visited = new HashSet<>();

        workList.add(category);
        while (!workList.isEmpty()) {
            var curCategory = workList.remove(0);
            result.addAll(Arrays.asList(curCategory.getDataTypes()));
            if (!visited.contains(curCategory)) {
                visited.add(curCategory);
                workList.addAll(Arrays.asList(curCategory.getCategories()));
            }
        }
    }

    /**
     * Get all built-in common types used in lib functions.
     * @return a set of built-in common types
     */
    public static Set<DataType> getLibraryTypes() {
        Set <DataType> result = new HashSet<>();
        var dtm = Global.currentProgram.getDataTypeManager();
        var rootCategory = dtm.getRootCategory();
        for (var category : rootCategory.getCategories()) {
            Logging.info("DataTypeHelper", "Category: " + category.getName());
            if (!category.getName().equals("DWARF")) {
                traverseTypeCategory(result, category);
            }
        }
        return result;
    }

    /**
     * Get all User defined types in the current program.
     * We think a type is user defined if it's in the DWARF category and not in the
     * ghidra's generic_clib_64 category.
     * @return a set of User defined types
     */
    public static Set<DataType> getAllUserDefinedTypes() {
        Set<DataType> libTypes = getLibraryTypes();
        Set<String> builtInLibTypeNames = new HashSet<>();
        for (var dt : libTypes) {
            builtInLibTypeNames.add(dt.getName());
        }

        Set<DataType> dwarfDataTypes = new HashSet<>();
        var dtm = Global.currentProgram.getDataTypeManager();

        var rootCategory = dtm.getRootCategory();
        for (var category : rootCategory.getCategories()) {
            if (category.getName().equals("DWARF")) {
                traverseTypeCategory(dwarfDataTypes, category);
            }
        }

        Set<DataType> result = new HashSet<>();
        for (var dt : dwarfDataTypes) {
            if (builtInLibTypeNames.contains(getBaseDataType(dt).getName())) {
                Logging.warn("DataTypeHelper", "Built-in lib type detected: " + dt.getName());
            } else {
                result.add(dt);
            }
        }

        return result;
    }


    /**
     * Get all User defined complex types in the current program.
     * We should be careful that in ghidra, function definition is also a DataType's subclass FunctionDefinition,
     * so we need to filter them out.
     * @return a set of User defined complex types
     */
    public static Set<DataType> getAllUserDefinedCompositeTypes() {
        Set<DataType> result = new HashSet<>();
        var allUserDefinedTypes = getAllUserDefinedTypes();
        for (var dt : allUserDefinedTypes) {
            if (dt instanceof Composite) {
                result.add(dt);
            } else if (dt instanceof FunctionDefinition) {
                Logging.debug("DataTypeHelper", "FunctionDefinition detected: " + dt.getName());
            } else if (dt instanceof TypeDef typedef) {
                var baseDT = typedef.getBaseDataType();
                if (baseDT instanceof Composite) {
                    result.add(baseDT);
                }
            }
        }

        return result;
    }

    public static DataType getTypeDefBaseDataType(DataType dt) {
        if (dt instanceof TypeDef typedef) {
            return getTypeDefBaseDataType(typedef.getBaseDataType());
        }
        return dt;
    }

    public static boolean isCompositeOrArray(DataType dt) {
        if (dt instanceof TypeDef typDef) {
            dt = typDef.getBaseDataType();
            return isCompositeOrArray(dt);
        }

        return dt instanceof Structure || dt instanceof Array || dt instanceof Union;
    }

    public static boolean isPointerToCompositeDataType(DataType dt) {
        if (dt instanceof Pointer pointer) {
            return isCompositeOrArray(pointer.getDataType());
        }
        return false;
    }
}
