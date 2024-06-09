package blueprint.utils;

import ghidra.program.model.data.*;

import java.util.*;

public class DataTypeHelper {

    /**
     * Check if the data type is a complex type or a pointer pointing to a complex type.
     * Complex type includes structure, union, array, etc.
     * @param dt the data type
     * @return true/false
     */
    public static boolean isComplexTypeAware(DataType dt) {
        if (dt instanceof Pointer pointer) {
            return isComplexTypeAware(pointer.getDataType());

        } else if (dt instanceof TypeDef typedef) {
            return isComplexTypeAware(typedef.getBaseDataType());

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
    public static Set<DataType> getBuiltInLibTypes() {
        Set <DataType> result = new HashSet<>();
        var dtm = Global.currentProgram.getDataTypeManager();
        var rootCategory = dtm.getRootCategory();
        for (var category : rootCategory.getCategories()) {
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
        Set<DataType> builtInLibTypes = getBuiltInLibTypes();
        Set<String> builtInLibTypeNames = new HashSet<>();
        for (var dt : builtInLibTypes) {
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
    public static Set<DataType> getAllUserDefinedComplexTypes() {
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


    public boolean isDecompilerRecoveredCompositeType(DataType dt) {
        return dt instanceof Structure || dt instanceof Array || dt instanceof Union;
    }
}
