package typeforge.base.dataflow.TFG;

import generic.stl.Pair;
import typeforge.base.dataflow.constraint.Skeleton;
import typeforge.base.dataflow.expression.NMAE;
import typeforge.base.dataflow.expression.NMAEManager;
import typeforge.utils.Logging;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.*;

public class TFGManager {
    private final Set<TypeFlowGraph<NMAE>> graphs;
    private final Map<NMAE, TypeFlowGraph<NMAE>> exprToGraph;

    public TFGManager() {
        this.graphs = new HashSet<>();
        this.exprToGraph = new HashMap<>();
    }

    public void addEdge(NMAE from, NMAE to, TypeFlowGraph.EdgeType type) {
        TypeFlowGraph<NMAE> fromGraph = exprToGraph.get(from);
        TypeFlowGraph<NMAE> toGraph = exprToGraph.get(to);
        if (fromGraph == null && toGraph == null) {
            TypeFlowGraph<NMAE> newGraph = new TypeFlowGraph<NMAE>();
            newGraph.addEdge(from, to, type);
            graphs.add(newGraph);
            exprToGraph.put(from, newGraph);
            exprToGraph.put(to, newGraph);
        } else if (fromGraph == null) {
            toGraph.addEdge(from, to, type);
            exprToGraph.put(from, toGraph);
        } else if (toGraph == null) {
            fromGraph.addEdge(from, to, type);
            exprToGraph.put(to, fromGraph);
        } else if (fromGraph != toGraph) {
            for (var node: toGraph.getNodes()) {
                exprToGraph.put(node, fromGraph);
            }
            fromGraph.mergeGraph(toGraph);
            graphs.remove(toGraph);
            fromGraph.addEdge(from, to, type); // `mergeGraphs` should be called before `addEdge`
        } else {
            // fromGraph == toGraph
            fromGraph.addEdge(from, to, type);
        }
    }

    public void removeEdge(NMAE from, NMAE to) {
        TypeFlowGraph<NMAE> fromGraph = exprToGraph.get(from);
        TypeFlowGraph<NMAE> toGraph = exprToGraph.get(to);
        if (fromGraph != null && fromGraph == toGraph) {
            fromGraph.removeEdge(from, to);
        }
    }

    public Set<Pair<NMAE, NMAE>> removeAllEdgesOfNode(NMAE node) {
        var removedEdges = new HashSet<Pair<NMAE, NMAE>>();
        Logging.debug("TFGManager", String.format("Removing all edges of node %s", node));

        TypeFlowGraph<NMAE> graph = exprToGraph.get(node);
        if (graph != null) {
            var inEdges = graph.getGraph().incomingEdgesOf(node);
            // Important: make a copy of the inEdges set to avoid ConcurrentModificationException
            for (var edge: new ArrayList<>(inEdges)) {
                var source = graph.getGraph().getEdgeSource(edge);
                graph.removeEdge(source, node);
                removedEdges.add(new Pair<>(source, node));
            }

            var outEdges = graph.getGraph().outgoingEdgesOf(node);
            for (var edge: new ArrayList<>(outEdges)) {
                var target = graph.getGraph().getEdgeTarget(edge);
                graph.removeEdge(node, target);
                removedEdges.add(new Pair<>(node, target));
            }
        }

        return removedEdges;
    }

    public Set<NMAE> getForwardNeighbors(NMAE node) {
        var graph = exprToGraph.get(node);
        var result = new HashSet<NMAE>();

        if (graph != null) {
            for (var edge: graph.getGraph().outgoingEdgesOf(node)) {
                if (edge.getType() == TypeFlowGraph.EdgeType.DATAFLOW ||
                        edge.getType() == TypeFlowGraph.EdgeType.CALL ||
                        edge.getType() == TypeFlowGraph.EdgeType.RETURN) {
                    var target = graph.getGraph().getEdgeTarget(edge);
                    result.add(target);
                }
            }
        }

        return result;
    }

    public Set<NMAE> getBackwardNeighbors(NMAE node) {
        var graph = exprToGraph.get(node);
        var result = new HashSet<NMAE>();

        if (graph != null) {
            for (var edge: graph.getGraph().incomingEdgesOf(node)) {
                if (edge.getType() == TypeFlowGraph.EdgeType.DATAFLOW ||
                        edge.getType() == TypeFlowGraph.EdgeType.CALL ||
                        edge.getType() == TypeFlowGraph.EdgeType.RETURN) {
                    var source = graph.getGraph().getEdgeSource(edge);
                    result.add(source);
                }
            }
        }

        return result;
    }


    public boolean hasEdge(NMAE from, NMAE to) {
        TypeFlowGraph<NMAE> fromGraph = exprToGraph.get(from);
        TypeFlowGraph<NMAE> toGraph = exprToGraph.get(to);
        return fromGraph != null && fromGraph == toGraph;
    }

    /**
     * Since some edges are removed during analysis.
     * For these changed graphs, we need to re-organize and split them into multiple graphs.
     * we need to re-organize the graphs by connected nodes.
     */
    // TODO: only re-organize the graphs which are changed
    public void reOrganize() {
        // A set to hold the new reorganized graphs
        Set<TypeFlowGraph<NMAE>> newGraphs = new HashSet<>();
        // A map to track node assignments to new graphs
        Map<NMAE, TypeFlowGraph<NMAE>> newExprToGraph = new HashMap<>();

        // Process each existing graph - use a copy to avoid concurrent modification
        for (TypeFlowGraph<NMAE> originalGraph : new ArrayList<>(graphs)) {
            // Get connected components
            List<Set<NMAE>> components = originalGraph.getConnectedComponents();

            // Process each disconnected component
            for (Set<NMAE> component : components) {
                if (component.isEmpty()) continue;

                // Create a new graph for this component
                TypeFlowGraph<NMAE> newGraph = new TypeFlowGraph<>();

                if (component.size() == 1) {
                    Logging.debug("TFGManager",
                            String.format("Found a single node graph %s", component));
                }

                // Add nodes from this component
                for (NMAE node : component) {
                    newGraph.getGraph().addVertex(node);
                    newExprToGraph.put(node, newGraph);
                }

                // Add edges that connect nodes within this component
                for (TypeFlowGraph.TypeFlowEdge edge : originalGraph.getGraph().edgeSet()) {
                    NMAE source = originalGraph.getGraph().getEdgeSource(edge);
                    NMAE target = originalGraph.getGraph().getEdgeTarget(edge);
                    if (component.contains(source) && component.contains(target)) {
                        newGraph.addEdge(source, target, edge.getType());
                    }
                }

                newGraphs.add(newGraph);
                Logging.debug("TFGManager",
                        String.format("Created new graph %s with %d nodes from disconnected component",
                                newGraph, newGraph.getNumNodes()));
            }
        }

        // Update class fields
        graphs.clear();
        graphs.addAll(newGraphs);
        exprToGraph.clear();
        exprToGraph.putAll(newExprToGraph);

        simpleTFGStatistics();
    }

    /**
     * Reorganize a specific TFG into multiple graphs based on connected components.
     * Updates the graphs and exprToGraph collections accordingly.
     *
     * @param graph The graph to reorganize
     * @return A set of newly created TypeFlowGraphs
     */
    public Set<TypeFlowGraph<NMAE>> reOrganizeTFG(TypeFlowGraph<NMAE> graph) {
        // A set to hold the new reorganized graphs
        Set<TypeFlowGraph<NMAE>> newGraphs = new HashSet<>();

        if (!graphs.contains(graph)) {
            Logging.warn("TFGManager", "The provided graph is not managed by this TFGManager");
            return newGraphs;
        }

        // Get connected components of the graph
        List<Set<NMAE>> components = graph.getConnectedComponents();

        // Process each disconnected component
        for (Set<NMAE> component : components) {
            if (component.isEmpty()) continue;

            // Create a new graph for this component
            TypeFlowGraph<NMAE> newGraph = new TypeFlowGraph<>();

            if (component.size() == 1) {
                Logging.debug("TFGManager",
                        String.format("Found a single node graph %s", component));
            }

            // Add nodes from this component
            for (NMAE node : component) {
                newGraph.getGraph().addVertex(node);
                exprToGraph.put(node, newGraph);
            }

            // Add edges that connect nodes within this component
            for (TypeFlowGraph.TypeFlowEdge edge : graph.getGraph().edgeSet()) {
                NMAE source = graph.getGraph().getEdgeSource(edge);
                NMAE target = graph.getGraph().getEdgeTarget(edge);
                if (component.contains(source) && component.contains(target)) {
                    newGraph.addEdge(source, target, edge.getType());
                }
            }

            newGraphs.add(newGraph);

            Logging.debug("TFGManager",
                    String.format("Created new graph %s with %d nodes from disconnected component",
                            newGraph, newGraph.getNumNodes()));
        }

        graphs.addAll(newGraphs);
        graphs.remove(graph);

        return newGraphs;
    }

    public boolean isProcessableGraph(TypeFlowGraph<NMAE> graph) {
        if (graph.getNumNodes() <= 1) {
            return false;
        }
        if (!graph.isValid()) {
            Logging.error("LayoutPropagator", String.format("Unexpected Invalid Graph %s, skip it.", graph));
            return false;
        }
        return true;
    }

    public boolean tryToMergeAllNodesSkeleton(TypeFlowGraph<NMAE> graph, Set<NMAE> graphNodes, NMAEManager exprManager) {
        var mergedSkeleton = new Skeleton();
        for (var node: graphNodes) {
            var nodeSkt = exprManager.getSkeleton(node);
            if (nodeSkt == null) continue;

            var success = mergedSkeleton.tryMergeLayoutStrict(nodeSkt);
            if (!success) {
                // IMPORTANT: If not success in merging, means some conflict nodes are not detected by previous propagateLayoutFromSourcesBFS.
                // This is because if the mergedSkeleton from different source has no intersection in their path, their conflicts will not be detected.
                // So we need to rebuild the path Manager there and detect them.
                Logging.warn("LayoutPropagator",
                        String.format("Graph: %s (%d) need to be processed to avoid conflicts further.", graph, graphNodes.size()));
                graph.finalSkeleton = null;
                return false;
            }
        }

        graph.finalSkeleton = mergedSkeleton;
        return true;
    }

    public TypeFlowGraph<NMAE> getTFG(NMAE node) {
        return exprToGraph.get(node);
    }

    public Set<TypeFlowGraph<NMAE>> getGraphs() {
        return graphs;
    }

    public void initAllPathManagers() {
        for (var graph: graphs) {
            if (graph.getNumNodes() > 1) {
                graph.pathManager.initialize();
            }
        }
    }

    /**
     * Find all nodes which are reachable target node within a given maxDepth.
     * @param target The target node
     * @param maxDepth The maxDepth of the search
     * @return A set of reachable nodes
     */
    public Set<NMAE> findReachableNodes(NMAE target, int maxDepth) {
        TypeFlowGraph<NMAE> graph = exprToGraph.get(target);
        if (graph == null) {
            return Collections.emptySet();
        }

        Set<NMAE> reachableNodes = new HashSet<>();
        // Include the target node itself
        reachableNodes.add(target);

        Queue<NMAE> queue = new LinkedList<>();
        Map<NMAE, Integer> distances = new HashMap<>();
        queue.add(target);
        distances.put(target, 0);

        while (!queue.isEmpty()) {
            NMAE current = queue.poll();
            int currentDistance = distances.get(current);

            if (currentDistance < maxDepth) {
                // Look at all incoming edges (reverse direction)
                for (TypeFlowGraph.TypeFlowEdge edge : graph.getGraph().incomingEdgesOf(current)) {
                    TypeFlowGraph.EdgeType edgeType = edge.getType();

                    // Only follow DATAFLOW, CALL, or RETURN edges
                    if (edgeType == TypeFlowGraph.EdgeType.DATAFLOW ||
                            edgeType == TypeFlowGraph.EdgeType.CALL ||
                            edgeType == TypeFlowGraph.EdgeType.RETURN) {

                        NMAE source = graph.getGraph().getEdgeSource(edge);
                        if (!distances.containsKey(source)) {
                            distances.put(source, currentDistance + 1);
                            reachableNodes.add(source);
                            queue.add(source);
                        }
                    }
                }
            }
        }

        return reachableNodes;
    }

    /**
     * Check if there is a data flow path from one node to another.
     * @param from The source node
     * @param to The target node
     * @return True if there is a data flow path, false otherwise
     */
    public boolean hasDataFlowPath(NMAE from, NMAE to) {
        // Check if both nodes are in the same graph
        TypeFlowGraph<NMAE> fromGraph = exprToGraph.get(from);
        TypeFlowGraph<NMAE> toGraph = exprToGraph.get(to);

        if (fromGraph == null || toGraph == null || fromGraph != toGraph) {
            return false;
        }

        // If they're the same node, return true
        if (from.equals(to)) {
            return true;
        }

        // BFS to find a path from 'from' to 'to' following relevant edges
        Queue<NMAE> queue = new LinkedList<>();
        Set<NMAE> visited = new HashSet<>();

        queue.add(from);
        visited.add(from);

        while (!queue.isEmpty()) {
            NMAE current = queue.poll();

            // Check all outgoing edges
            for (TypeFlowGraph.TypeFlowEdge edge : fromGraph.getGraph().outgoingEdgesOf(current)) {
                TypeFlowGraph.EdgeType edgeType = edge.getType();

                // Only follow DATAFLOW, CALL, or RETURN edges
                if (edgeType == TypeFlowGraph.EdgeType.DATAFLOW ||
                        edgeType == TypeFlowGraph.EdgeType.CALL ||
                        edgeType == TypeFlowGraph.EdgeType.RETURN) {

                    NMAE target = fromGraph.getGraph().getEdgeTarget(edge);

                    // If we've reached the destination, return true
                    if (target.equals(to)) {
                        return true;
                    }

                    // If we haven't visited this node yet, add it to the queue
                    if (!visited.contains(target)) {
                        visited.add(target);
                        queue.add(target);
                    }
                }
            }
        }

        // No path found
        return false;
    }

    /**
     * If a graph has no nodes with fields, it is redundant and should be removed.
     * @param baseToFieldsMap A map from base to its fields
     */
    public void removeRedundantGraphs(Map<NMAE, TreeMap<Long, Set<NMAE>>> baseToFieldsMap) {
        Set<TypeFlowGraph<NMAE>> toRemove = new HashSet<>();
        for (var graph: graphs) {
            boolean hasInterestedNode = false;
            for (var node: graph.getNodes()) {
                if (baseToFieldsMap.containsKey(node) && !baseToFieldsMap.get(node).isEmpty()) {
                    hasInterestedNode = true;
                    break;
                }
            }
            if (!hasInterestedNode) {
                Logging.trace("TypeRelationManager", String.format("Remove redundant graph %s", graph));
                toRemove.add(graph);
            }
        }

        for (var graph: toRemove) {
            graphs.remove(graph);
            for (var node: graph.getNodes()) {
                exprToGraph.remove(node);
            }
        }
    }

    /**
     * Statistics Node and Edge information for TFGs
     */
    public void simpleTFGStatistics() {
        var totalNodes = 0;
        var totalEdges = 0;

        Logging.info("TFGManager", "=========================================");
        Logging.info("TFGManager", "TFG Statistics:");
        Logging.info("TFGManager", "Total number of TFGs: " + graphs.size());
        for (var graph: graphs) {
            totalNodes += graph.getNumNodes();
            totalEdges += graph.getGraph().edgeSet().size();
        }
        Logging.info("TFGManager", "Total number of nodes: " + totalNodes);
        Logging.info("TFGManager", "Total number of edges: " + totalEdges);
        Logging.info("TFGManager", "=========================================");
    }

    /**
     * Dump the partial TFG for a given NMAE node into one DOT file.
     * @param node The node to dump the TFG for
     * @param depth Max graph edge depth around the node
     * @param outputDir The directory to dump the TFG information
     */
    public void dumpPartialTFG(NMAE node, int depth, File outputDir) {
        TypeFlowGraph<NMAE> graph = exprToGraph.get(node);
        if (graph == null) {
            Logging.error("TFGManager", "No TFG found for node: " + node);
            return;
        }
        File graphFile = new File(outputDir, "Partial_TFG_" + node.toString() + ".dot");
        try {
            Files.write(graphFile.toPath(), graph.toPartialGraphviz(node, depth).getBytes());
        } catch (IOException e) {
            Logging.error("TFGManager", "Failed to write TFG to file: " + e);
            e.printStackTrace();
        }
    }


    /**
     * Dump all TFG information as DOT files into the user-specified directory.
     * Metadata is stored in TFGManager.json.
     * @param outputDir The directory to dump the TFG information
     * @throws IOException If the output directory is not valid or the file cannot be written
     */
    public void dumpFullTFG(File outputDir) throws IOException {
        File metadataFile = new File(outputDir, "TFGManager.json");

        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);

        Map<String, Object> metadata = new HashMap<>();
        Map<String, String> exprToGraphID = new HashMap<>();
        List<String> graphIDs = new ArrayList<>();

        for (var entry: exprToGraph.entrySet()) {
            exprToGraphID.put(entry.getKey().toString(), entry.getValue().toString());
        }
        for (var graph: graphs) {
            graphIDs.add("TypeFlowGraph_" + graph.getShortUUID());
        }
        metadata.put("graphs", graphIDs);
        metadata.put("exprToGraph", exprToGraphID);
        mapper.writeValue(metadataFile, metadata);

        if (graphs.size() != exprToGraph.values().stream().distinct().count()) {
            Logging.error("TFGManager", "Graphs and exprToGraph are inconsistent");
            System.exit(1);
        }

        for (var graph: graphs) {
            String graphName = "TypeFlowGraph_" + graph.getShortUUID();
            File graphFile = new File(outputDir, graphName + ".dot");
            Files.write(graphFile.toPath(), graph.toGraphviz().getBytes());
        }
    }


    public void dumpEntryToExitPaths(File outputDir) {
        File textFile = new File(outputDir, "EntryToExitPaths.txt");

        try (FileWriter writer = new FileWriter(textFile)) {
            for (var graph: graphs) {
                graph.pathManager.dump(writer);
                writer.write("\n ----------------------------------------------------------- \n");
            }
        } catch (Exception e) {
            Logging.error("TFGManager", "Failed to write entry to exit paths to file" + e);
            e.printStackTrace();
            System.exit(1);
        }
    }
}
