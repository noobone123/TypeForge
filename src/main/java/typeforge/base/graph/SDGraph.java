package typeforge.base.graph;

import java.util.*;

import typeforge.base.node.DataTypeNode;
import typeforge.base.node.NodeBase;
import typeforge.utils.Logging;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;

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
        Logging.debug("SDGraph", root.toString());
        if (!(root instanceof Structure st)) {
            Logging.error("SDGraph", "The root data type is not a structure");
            return;
        }

        buildAll(st);
    }

    /**
     * Build the SDGraph for the given root, build recursively.
     */
    private void buildAll(Structure root) {
        LinkedList<DataTypeNode> workList = new LinkedList<>();
        HashSet<DataTypeNode> visited = new HashSet<>();

        DataTypeNode rootNode = (DataTypeNode) getNode(root);

        workList.add(rootNode);
        while (!workList.isEmpty()) {
            DataTypeNode cur = workList.poll();
            if (cur.value instanceof Structure st) {
                handleStructureNode(cur, st, workList, visited);
            } else if (cur.value instanceof Array array) {
                throw new UnsupportedOperationException("Array is not supported yet");
            } else if (cur.value instanceof Union union) {
                throw new UnsupportedOperationException("Union is not supported yet");
            } else {
                throw new UnsupportedOperationException("Unsupported data type");
            }
        }
    }


    /**
     * Traverse the fields of structure node and try to build the SDGraph.
     * @param node the object of DataTypeNode
     * @param st the structure DataType
     * @param workList the worklist for building the SDGraph
     */
    private void handleStructureNode(DataTypeNode node, Structure st,
                                     LinkedList<DataTypeNode> workList,
                                     HashSet<DataTypeNode> visited)
    {
        for (var dtc : st.getDefinedComponents()) {
            DataType fieldDT = dtc.getDataType();

            if (fieldDT instanceof BuiltInDataType) {
                continue;

            } else if (fieldDT instanceof Pointer ptr) {
                // TODO: consider to handle multiple pointers? especially for **
                // TODO: pointer should be handled differently from other types
                DataType pointedDT = ptr.getDataType();
                if (pointedDT instanceof Structure pointedST) {
                    Logging.debug("SDGraph", "Reference: " + fieldDT + " offset: " + dtc.getOffset());
                    DataTypeNode dstNode = (DataTypeNode) getNode(pointedST);
                    addEdge(node, dstNode, EdgeType.REFERENCE, dtc.getOffset());
                    if (!visited.contains(dstNode)) {
                        workList.add(dstNode);
                        visited.add(dstNode);
                    }
                }
                // TODO: handle other types of pointer

            } else if (fieldDT instanceof Array) {
                continue;

            } else if (fieldDT instanceof Structure fst) {
                DataTypeNode dstNode = (DataTypeNode) getNode(fst);
                Logging.debug("SDGraph", "Nested: " + fst.getName() + " offset: " + dtc.getOffset());
                addEdge(node, dstNode, EdgeType.NESTED, dtc.getOffset());
                if (!visited.contains(dstNode)) {
                    workList.add(dstNode);
                    visited.add(dstNode);
                }

            } else if (fieldDT instanceof Union) {
                continue;

            } else if (fieldDT instanceof FunctionDefinition) {
                continue;

            } else if (fieldDT instanceof Enum) {
                continue;

            } else if (fieldDT instanceof TypeDef) {
                continue;

            } else if (fieldDT instanceof BitFieldDataType) {
                continue;

            } else {
                Logging.error("SDGraph", "Unsupported data type: " + fieldDT);
            }
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

    public static class SDEdge {
        public final DataTypeNode srcNode;
        public final DataTypeNode dstNode;
        public final EdgeType edgeType;
        public final int offset;

        public SDEdge(DataTypeNode srcNode, DataTypeNode dstNode, EdgeType edgeType, int offset) {
            this.srcNode = srcNode;
            this.dstNode = dstNode;
            this.edgeType = edgeType;
            this.offset = offset;
        }

        @Override
        public String toString() {
            return "SDEdge{" +
                    "srcNode=" + srcNode +
                    ", dstNode=" + dstNode +
                    ", edgeType=" + edgeType +
                    ", offset=" + offset +
                    '}';
        }
    }

    /**
     * Add an edge to the SDGraph.
     * @param srcNode the source data type
     * @param dstNode the destination data type
     * @param edge_type the type of the edge
     * @param offset the offset of the dependency
     */
    public void addEdge(DataTypeNode srcNode, DataTypeNode dstNode, EdgeType edge_type, int offset) {
        if (srcNode.offsetToEdge.get(offset) != null) {
            Logging.warn("SDGraph", "The offset " + offset + " already exists in the srcNode");
            if (srcNode.offsetToEdge.get(offset).dstNode != dstNode) {
                Logging.error("SDGraph", "The offset " + offset + " already exists in the srcNode, but the dstNode is different");
            }
            return;
        }

        SDEdge edge = new SDEdge(srcNode, dstNode, edge_type, offset);
        srcNode.edges.add(edge);
        srcNode.offsetToEdge.put(offset, edge);
    }

    /**
     * Build and get all edges from the DataTypeNode's offsetNodeMap and offsetEdgeTypeMap.
     * @return a Set of edges
     */
    public Set<SDEdge> getAllEdges() {
        Set<NodeBase<DataType>> allNodes = getAllNodes();
        Set<SDEdge> allEdges = new HashSet<>();

        for (NodeBase<DataType> node : allNodes) {
            if (node instanceof DataTypeNode dtNode) {
                allEdges.addAll(dtNode.edges);
            }
        }

        return allEdges;
    }

    @Override
    protected NodeBase<DataType> createNode(DataType value, int node_id) {
        return new DataTypeNode(value, node_id);
    }
}
