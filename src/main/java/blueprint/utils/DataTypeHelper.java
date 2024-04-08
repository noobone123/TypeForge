package blueprint.utils;

import blueprint.utils.GlobalState;

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
            Logging.info("Pointer detected: " + pointer);
            return isComplexTypeAware(pointer.getDataType());

        } else if (dt instanceof TypeDef typedef) {
            Logging.info("Typedef detected: " + typedef.getName());
            return isComplexTypeAware(typedef.getBaseDataType());

        } else {
            if (dt instanceof Composite || dt instanceof Array) {
                Logging.info("Complex type detected: " + dt.getName());
                return true;
            } else {
                Logging.info("Simple type detected: " + dt.getName());
                return false;
            }
        }
    }

    /**
     * If the data type is a pointer, typedef or array, we should get the base data type.
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
            Logging.warn("Unexpected data type: " + dt.getName());
            return dt;
        }
    }

    /**
     * Get all User defined types in the current program.
     * We think a type is user defined if it's in the DWARF category.
     * @return a set of User defined types
     */
    // TODO： filter out types that are used in the standard library
    public static Set<DataType> getAllUserDefinedTypes() {
        Set<DataType> result = new HashSet<>();
        var dtm = GlobalState.currentProgram.getDataTypeManager();

        var rootCategory = dtm.getRootCategory();
        for (var category : rootCategory.getCategories()) {
            if (category.getName().equals("DWARF")) {
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
                Logging.debug("FunctionDefinition detected: " + dt.getName());
            } else if (dt instanceof TypeDef typedef) {
                var baseDT = typedef.getBaseDataType();
                if (baseDT instanceof Composite) {
                    result.add(baseDT);
                }
            }
        }

        return result;
    }
}
