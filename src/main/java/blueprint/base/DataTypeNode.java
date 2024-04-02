package blueprint.base;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;

import java.util.HashMap;
import java.util.Map;
import java.util.HashSet;
import java.util.Set;

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

    /** The pred nodes of each edge's type */
    public final Map<SDGraph.EdgeType, Set<DataTypeNode>> predMap = new HashMap<>();

    /** The succ nodes of each edge's type */
    public final Map<SDGraph.EdgeType, Set<DataTypeNode>> succMap = new HashMap<>();

    /** The map from offset to node */
    public final Map<Integer, DataTypeNode> offsetNodeMap = new HashMap<>();

    /** The map from offset to edge type */
    public final Map<Integer, SDGraph.EdgeType> offsetEdgeTypeMap = new HashMap<>();

    public DataTypeNode(DataType value, int id) {
        super(value, id);
    }
}
