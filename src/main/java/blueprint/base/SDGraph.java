package blueprint.base;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import blueprint.utils.GlobalState;

import blueprint.utils.Logging;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;

/**
 * Structure Dependency Graph
 */
public class SDGraph extends GraphBase<DataType> {

    /** The cache of SDGraphs */
    private static final Map<DataType, SDGraph> sdGraphCache = new HashMap<>();

    /**
     * Get the SDGraph of the given data type. If the SDGraph does
     * not exist, a new one will be created.
     * @param root the root data type of the SDGraph
     * @return the SDGraph
     */
    public static SDGraph getSDGraph(DataType root) {
        if (sdGraphCache.containsKey(root)) {
            return sdGraphCache.get(root);
        }
        SDGraph sdg = new SDGraph(root);
        sdGraphCache.put(root, sdg);
        return sdg;
    }

    /**
     * Create a SDGraph with the given root data type.
     * @param root the root data type
     */
    private SDGraph(DataType root) {
        Logging.info(root.toString());
        if (!(root instanceof Structure st)) {
            Logging.error("The root data type is not a structure");
            return;
        }
        Logging.info("This Structure has " + st.getNumDefinedComponents() + " defined components");
        for (var component : st.getDefinedComponents()) {
            Logging.info("Component: " + component.getDataType().toString() + " - " + component.getFieldName());
        }

    }

    public enum EdgeType {
        /**
         * SDG Graph has the following types of edges:
         * 1. Nested Edge: If a structure A contains a structure B, then there is a nested edge from A to B.
         * 2. Reference Edge: If a structure A contains a pointer to a structure B, then there is a reference edge from A to B.
         * 3. Union Edge: If a structure A contains a union B, then there is a union edge from A to B.
         * 4. Array Edge: If a structure A contains an array of other type B, then there is an array edge from A to B.
         * 5. FuncPtr Edge: If a structure A contains a function pointer to a function B, then there is a function edge from A to B.
         * 6. Enum Edge: If a structure A contains an enum B, then there is an enum edge from A to B.
         * 7. Normal Edge: If a structure A contains a primitive type pointer which points to B, then there is a normal edge from A to B.
       */
        NESTED, REFERENCE, UNION, ARRAY, FUNC_PTR, ENUM, NORMAL
    }

    /**
     * Add an edge to the SDGraph.
     * @param src the source data type
     * @param dst the destination data type
     * @param edge_type the type of the edge
     * @param offset the offset of the dependency
     */
    public void addEdge(DataType src, DataType dst, EdgeType edge_type, int offset) {
        DataTypeNode src_node = (DataTypeNode) getNode(src);
        DataTypeNode dst_node = (DataTypeNode) getNode(dst);

        if (src_node.offsetNodeMap.containsKey(offset)) {
            Logging.warn("The offset " + offset + " already exists in the source node");
            return;
        }

        src_node.offsetNodeMap.put(offset, dst_node);
        src_node.offsetEdgeTypeMap.put(offset, edge_type);
        src_node.succMap.computeIfAbsent(edge_type, k -> new HashSet<>()).add(dst_node);
        dst_node.predMap.computeIfAbsent(edge_type, k -> new HashSet<>()).add(src_node);
    }

    @Override
    protected NodeBase<DataType> createNode(DataType value, int node_id) {
        return new DataTypeNode(value, node_id);
    }
}
