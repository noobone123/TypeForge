package blueprint.solver;

import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.NoisyStructureBuilder;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.HashMap;
import java.util.Set;

/**
 * Context class for storing dataflow facts for a function
 */
public class Context {
    /**
     * For Example:
     * <p>
     *     HighVariable1 -> {
     *         Offset_1 -> Set of data types
     *         Offset_2 -> Set of data types
     *         ...
     *     }
     * </p>
     * We use Set to store data types because we may collect multiple data types at the same offset
     * in the analysis, due to the complex composite data types defined in the program.
     */
    private final HashMap<HighVariable, HashMap<Long, Set<DataType>>> structMap;

    public Context() {
        structMap = new HashMap<>();
    }

    /**
     * Add a data type to the context
     * @param highVar the base high variable
     * @param offset the offset of the field
     * @param dt the field's data type
     * @return true if the data type is added successfully
     */
    public boolean addDataType(HighVariable highVar, long offset, DataType dt) {
        if (!structMap.containsKey(highVar)) {
            structMap.put(highVar, new HashMap<>());
        }

        if (!structMap.get(highVar).containsKey(offset)) {
            structMap.get(highVar).put(offset, new HashSet<>());
        }

        return structMap.get(highVar).get(offset).add(dt);
    }


}
