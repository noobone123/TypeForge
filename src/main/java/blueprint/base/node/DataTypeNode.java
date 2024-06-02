package blueprint.base.node;

import blueprint.base.graph.SDGraph;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;

import java.util.*;

import blueprint.utils.Logging;

/**
 * In Structure Dependency Graph, each node has multiple edges to other nodes.
 * For example:
 * struct A {
 *     struct B b_1;     // struct B's size is 8 bytes
 *     struct *C c_1;
 *     struct *C c_2;
 * }
 * The above structure A has 3 edges:
 * 1. A -- Nested -- offset 0 --> B
 * 2. A -- Reference -- offset 8 --> C
 * 3. A -- Reference -- offset 12 --> C
 */
public class DataTypeNode extends NodeBase<DataType>{

    /** The map from field offset to field */
    public final Map<Integer, DataTypeComponent> fieldMap = new HashMap<>();

    /** The edges of the node */
    public Set<SDGraph.SDEdge> edges = new HashSet<>();

    /** The HashMap of offset to edge */
    public Map<Integer, SDGraph.SDEdge> offsetToEdge = new HashMap<>();

    public DataTypeNode(DataType value, int id) {
        super(value, id);
        Logging.info("DataTypeNode", "Creating DataTypeNode with value: " + value.getName());

        if (value instanceof Structure st) {
            fillFieldMap(st);
        }

    }

    private void fillFieldMap(Structure st) {
        for (var dtc : st.getDefinedComponents()) {
            fieldMap.put(dtc.getOffset(), dtc);
        }
    }
}
