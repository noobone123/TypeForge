package blueprint.solver;

import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.NoisyStructureBuilder;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.HashMap;

/**
 * Context class for storing dataflow facts for a function
 */
public class Context {
    /**
     * Map of HighSymbols to NoisyStructureBuilders
     * Each Function's context will have its own map
     */
    public HashMap<HighVariable, NoisyStructureBuilder> structMap;

    public Context() {
        structMap = new HashMap<>();
    }

}
