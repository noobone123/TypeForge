package typeforge.base.dataflow.TFG;

import generic.stl.Pair;
import org.jgrapht.GraphPath;
import typeforge.base.dataflow.expression.NMAE;
import typeforge.base.dataflow.expression.NMAEManager;
import typeforge.base.dataflow.UnionFind;
import typeforge.base.dataflow.constraint.TypeConstraint;
import typeforge.base.dataflow.solver.TypeHintCollector;
import typeforge.base.dataflow.constraint.Skeleton;
import typeforge.base.dataflow.Layout;
import typeforge.utils.Logging;
import org.jgrapht.alg.shortestpath.AllDirectedPaths;

import java.io.FileWriter;
import java.util.*;

public class TypeFlowPathManager<T> {
    public TypeFlowGraph<T> graph;

    /** Import metadata for TypeFlowPathManager, should be updated when graph changed */
    public final Set<T> source;
    public final Set<T> sink;
    public final Map<T, Set<TypeFlowPath<T>>> srcToPathsMap;
    public final Map<T, Skeleton> srcToMergedSkeleton;

    /** node to Skeletons when propagating layout information BFS */
    public final Map<T, Skeleton> nodeToMergedSkeleton;

    /** fields for handle conflict paths and nodes */
    public final Set<TypeFlowPath<T>> pathsHasConflict = new HashSet<>();

    /** fields for handle edges that introduce conflicts */
    public final Set<T> conflictSources = new HashSet<>();
    public final Set<T> conflictNonSourceNodes = new HashSet<>();
    public final Set<TypeFlowGraph.TypeFlowEdge> evilEdgesInPerPath = new HashSet<>();
    public final Set<TypeFlowGraph.TypeFlowEdge> evilEdgesInSourceAggregate = new HashSet<>();
    public final Set<TypeFlowGraph.TypeFlowEdge> evilEdgesInConflictNodes = new HashSet<>();
    public final Set<TypeFlowGraph.TypeFlowEdge> keepEdges = new HashSet<>();

    /** We do forward propagation which is enough, so we need to remove backward edges to avoid interference */
    public final Set<TypeFlowGraph.TypeFlowEdge> backwardEdges = new HashSet<>();

    /** Fields for build skeletons, not used for conflict checking
     * If source's PathNodes has common nodes, we should put them in one cluster using UnionFind */
    public UnionFind<T> sourceGroups = new UnionFind<>();
    public final Map<T, Set<T>> sourceToChildren = new HashMap<>();
    public final Map<T, Skeleton> sourceToConstraints = new HashMap<>();

    public TypeFlowPathManager(TypeFlowGraph<T> graph) {
        this.graph = graph;
        this.source = new HashSet<>();
        this.sink = new HashSet<>();
        this.srcToPathsMap = new HashMap<>();
        this.srcToMergedSkeleton = new HashMap<>();
        this.nodeToMergedSkeleton = new HashMap<>();
    }

    public void initialize() {
        Logging.debug("TypeFlowPathManager",
                String.format("Initialize TypeFlowPathManager for graph: %s", graph));
        this.source.clear();
        this.sink.clear();
        this.srcToPathsMap.clear();
        this.srcToMergedSkeleton.clear();
        this.nodeToMergedSkeleton.clear();

        findSourcesAndSinks();

        findAllPathFromSrcToSink();

        markAllBackwardEdges();
    }

    /**
     * Try merge Skeletons from each node along the same path
     * IMPORTANT: This Function should be called after all Graph's pathManager built
     */
    public void tryMergeLayoutFormSamePathsForward(NMAEManager exprManager) {
        Queue<TypeFlowPath<T>> workList = new LinkedList<>();

        Logging.info("TypeFlowPathManager", String.format("Try merge layout from same paths: %s", srcToPathsMap));

        // First phase: check all paths for conflicts
        for (var src: srcToPathsMap.keySet()) {
            for (var path: srcToPathsMap.get(src)) {
                var success = path.tryMergeLayoutForwardOnPath(exprManager);
                if (!success) {
                    pathsHasConflict.add(path);
                    evilEdgesInPerPath.add(path.conflictEdge);
                    path.conflict = true;
                    workList.add(path);
                }
            }
        }

        // Second phase: recursively process conflict paths using workList
        while (!workList.isEmpty()) {
            var path = workList.poll();
            if (!path.conflict || path.conflictEdge == null) continue;

            // Metadata will be updated in splitPathByEdge
            var newPaths = splitPathByEdge(path, path.conflictEdge);
            if (newPaths == null) continue;

            var pathPrefix = newPaths.first;
            var pathSuffix = newPaths.second;

            // Process prefix path
            var prefixSuccess = pathPrefix.tryMergeLayoutForwardOnPath(exprManager);
            if (!prefixSuccess) {
                pathsHasConflict.add(pathPrefix);
                pathPrefix.conflict = true;
                evilEdgesInPerPath.add(pathPrefix.conflictEdge);
                workList.add(pathPrefix); // Add back to workList for further processing
            }

            // Process suffix path
            var suffixSuccess = pathSuffix.tryMergeLayoutForwardOnPath(exprManager);
            if (!suffixSuccess) {
                pathsHasConflict.add(pathSuffix);
                pathSuffix.conflict = true;
                evilEdgesInPerPath.add(pathSuffix.conflictEdge);
                workList.add(pathSuffix); // Add back to workList for further processing
            }
        }
    }

    /**
     * Since a Source node in whole-program TFG may have multiple paths,
     * We should try to merge Skeletons from each path to build layout information of each source.
     * IMPORTANT: This Function should be called after `tryMergeLayoutFormSamePaths`,
     *              Now all paths get from `srcToPathsMap` has no conflicts.
     * @param exprManager NMAE Manager
     */
    public void tryMergeLayoutFromSameSourceForward(NMAEManager exprManager) {
        var workList = new LinkedList<>(source);

        while (!workList.isEmpty()) {
            var src = workList.poll();
            var mergedSkt = new Skeleton();

            // These valid edges does not contain paths with conflicts or noComposite
            var validPathsFromSrc = getAllValidPathsFromSource(src);
            if (validPathsFromSrc.isEmpty()) {
                continue;
            }

            var success = true;
            for (var path: validPathsFromSrc) {
                success = mergedSkt.tryMergeLayoutStrict(path.finalSkeletonOnPath);
                if (!success) {
                    break;
                }
            }

            if (success) {
                Logging.debug("TypeFlowPathManager", String.format("No Conflict when merging paths from same source: %s", src));
                srcToMergedSkeleton.put(src, mergedSkt);
            } else {
                Logging.debug("TypeFlowPathManager",
                        String.format("Found Conflict when merging paths from same source: %s, total paths: %d", src, validPathsFromSrc.size()));
                conflictSources.add(src);

                var LCP = getLongestCommonPrefixPath(validPathsFromSrc);
                Logging.debug("TypeFlowPathManager", String.format("Found common prefix path: %s", LCP));
                var intraLCPEdges = getEdgesInLCP(LCP, validPathsFromSrc);
                keepEdges.addAll(intraLCPEdges);

                for (var path: validPathsFromSrc) {
                    Logging.debug("TypeFlowPathManager", String.format("Split path: %s", path));
                    var LCPEndEdge = getEndEdgeOfLCP(LCP, path);
                    if (LCPEndEdge == null) continue;
                    evilEdgesInSourceAggregate.add(LCPEndEdge);
                    var newPaths = splitPathByEdge(path, LCPEndEdge);
                    if (newPaths == null) continue;
                    var pathPrefix = newPaths.first;
                    var pathSuffix = newPaths.second;

                    // Due to workList process in `tryMergeLayoutFormSamePaths`, now these split paths should not have conflicts
                    var pathPrefixSuccess = pathPrefix.tryMergeLayoutForwardOnPath(exprManager);
                    var pathSuffixSuccess = pathSuffix.tryMergeLayoutForwardOnPath(exprManager);
                    if (!pathPrefixSuccess || !pathSuffixSuccess) {
                        Logging.error("TypeFlowPathManager", "These should not happen ....");
                    }

                    workList.add(pathPrefix.start);
                    workList.add(pathSuffix.start);
                }
            }
        }
    }

    /**
     * This method should be call after `tryMergeLayoutFromSameSource`.
     * In theory, all merged skeletons from the source nodes should not have conflicts at this point.
     * When we detect conflict nodes during following propagation process, we remove all edges connected to them.
     * At this stage, the remaining connected components in the graph should theoretically also be free of conflicts
     */
    // TODO:
    //  1. 如果 Source 之间的路径没有任何节点的交集，那么它们之间实际上无法相互传播，因此也就无法检查到冲突。
    public void propagateLayoutFromSourcesBFS() {
        if (srcToMergedSkeleton.isEmpty()) {
            Logging.debug("TypeFlowPathManager", "No merged skeletons to propagate");
            return;
        }

        // Track source nodes and their border nodes
        Map<T, Set<T>> sourceToBorderNodes = new HashMap<>();
        // Initialize border nodes as source nodes themselves
        for (var src : srcToMergedSkeleton.keySet()) {
            var borderNodes = new HashSet<T>();
            nodeToMergedSkeleton.put(src, srcToMergedSkeleton.get(src));
            borderNodes.add(src);
            sourceToBorderNodes.put(src, borderNodes);
        }

        // Track propagated nodes to avoid repetition
        Map<T, Set<T>> sourceToPropagatedNodes = new HashMap<>();
        for (var src : srcToMergedSkeleton.keySet()) {
            sourceToPropagatedNodes.put(src, new HashSet<>());
            sourceToPropagatedNodes.get(src).add(src);
        }

        // Process sources in deterministic order
        List<T> sortedSources = new ArrayList<>(srcToMergedSkeleton.keySet());
        sortedSources.sort(Comparator.comparing(Object::hashCode));

        boolean hasNewBorderNode = true;
        while (hasNewBorderNode) {
            hasNewBorderNode = false;

            for (var source : sortedSources) {
                var currentBorderNodes = sourceToBorderNodes.get(source);
                var newBorderNodes = new HashSet<T>();

                List<T> sortedBorderNodes = new ArrayList<>(currentBorderNodes);
                sortedBorderNodes.sort(Comparator.comparing(Object::hashCode));

                for (var borderNode : sortedBorderNodes) {
                    // IMPORTANT: These nodes should not be seen as border nodes, so layout information
                    // will not be propagated from them
                    if (conflictNonSourceNodes.contains(borderNode)) continue;

                    var borderSkt = nodeToMergedSkeleton.get(borderNode);

                    // TODO: check if there are any
                    Set<T> neighbors = new HashSet<>(graph.getForwardNeighbors(borderNode));
                    List<T> sortedNeighbors = new ArrayList<>(neighbors);
                    sortedNeighbors.sort(Comparator.comparing(Object::hashCode));

                    for (var neighbor: sortedNeighbors) {
                        if (sourceToPropagatedNodes.get(source).contains(neighbor)) continue;

                        var neighborSkts = nodeToMergedSkeleton.get(neighbor);
                        // Not propagated yet
                        if (neighborSkts == null) {
                            nodeToMergedSkeleton.put(neighbor, nodeToMergedSkeleton.get(borderNode));
                            newBorderNodes.add(neighbor);
                            sourceToPropagatedNodes.get(source).add(neighbor);
                        }
                        // If Already propagated with a Skeleton
                        else {
                            var neighborSkt = nodeToMergedSkeleton.get(neighbor);

                            // IMPORTANT: Since skeletons current propagated are already merged from paths.
                            //  So merging operation should not be too strict.
                            //  Anyway, changing it into `tryMergeLayoutStrict` is also ok.
                            boolean success = neighborSkt.tryMergeLayoutRelax(borderSkt);
                            if (success) {
                                nodeToMergedSkeleton.put(neighbor, neighborSkt);
                                newBorderNodes.add(neighbor);
                                sourceToPropagatedNodes.get(source).add(neighbor);
                            } else {
                                Logging.debug("TypeFlowPathManager",
                                        String.format("Layout conflict when propagating from %s -> %s",
                                                borderNode, neighbor));
                                Logging.debug("TypeFlowPathManager",
                                        String.format("Border Skeleton: \n%s", borderSkt.dumpLayout(2)));
                                Logging.debug("TypeFlowPathManager",
                                        String.format("Neighbor Skeleton: \n%s", neighborSkt.dumpLayout(2)));

                                conflictNonSourceNodes.add(neighbor);
                                sourceToPropagatedNodes.get(source).add(neighbor);
                            }
                        }
                    }
                }

                // Update frontier if new nodes were found
                if (!newBorderNodes.isEmpty()) {
                    sourceToBorderNodes.get(source).addAll(newBorderNodes);
                    hasNewBorderNode = true;
                }
            }
        }

        // Post-processing, marking nodes that are not propagated to.
        var propagatedNodes = nodeToMergedSkeleton.keySet();
        var allNodes = graph.getGraph().vertexSet();
        var notPropagatedNodes = new HashSet<T>(allNodes);
        notPropagatedNodes.removeAll(propagatedNodes);
        if (!notPropagatedNodes.isEmpty()) {
            Logging.info("TypeFlowPathManager",
                    String.format("%s: Found %d nodes that are not propagated to: %s",
                            graph, notPropagatedNodes.size(), notPropagatedNodes));
            Logging.info("TypeFlowPathManager",
                    String.format("Sources size: %d, Sinks size: %d", source.size(), sink.size()));
            Logging.info("TypeFlowPathManager",
                    String.format("Sources are: %s", source));
            Logging.info("TypeFlowPathManager",
                    String.format("Sinks are: %s", sink));
        }

        // Post-processing, updating conflict Nodes
        if (!conflictNonSourceNodes.isEmpty()) {
            Logging.info("TypeFlowPathManager",
                    String.format("Found %d conflict Non-Source nodes during Layout Information Propagation: %s", conflictNonSourceNodes.size(), conflictNonSourceNodes));

            // Remove all edges connected to conflict nodes
            for (var node: conflictNonSourceNodes) {
                var inEdges = graph.getGraph().incomingEdgesOf(node);
                var outEdges = graph.getGraph().outgoingEdgesOf(node);
                for (var edge: inEdges) {
                    if (keepEdges.contains(edge)) continue;
                    evilEdgesInConflictNodes.add(edge);
                }

                for (var edge: outEdges) {
                    if (keepEdges.contains(edge)) continue;
                    evilEdgesInConflictNodes.add(edge);
                }
            }
        }
    }

    /**
     * Check if there are any conflicts when merging all skeletons from the source nodes.
     */
    public void checkSourceSkeletonCorrectness(NMAEManager exprManager) {
        // Re-initialize ...
        initialize();

        // First phase: check all paths for conflicts
        for (var src: srcToPathsMap.keySet()) {
            for (var path: srcToPathsMap.get(src)) {
                var success = path.tryMergeLayoutForwardOnPath(exprManager);
                if (!success) {
                    Logging.error("TypeFlowPathManager", "Unexpected error in checking paths conflicts.");
                    break;
                }
            }
        }

        // Second phase: check all merged sources for conflicts.
        for (var src: srcToPathsMap.keySet()) {
            var mergedSkt = new Skeleton();
            for (var path: srcToPathsMap.get(src)) {
                var success = mergedSkt.tryMergeLayoutStrict(path.finalSkeletonOnPath);
                if (!success) {
                    Logging.error("TypeFlowPathManager", "Unexpected error in merging source's skeletons.");
                    break;
                }
            }
            srcToMergedSkeleton.put(src, mergedSkt);
        }
    }

    /**
     * This method is actually very similar to tryMergeOnPath
     * @param exprManager SymbolExprManager
     */
    public void mergeOnPath(NMAEManager exprManager) {
        for (var src: srcToPathsMap.keySet()) {
            for (var path: srcToPathsMap.get(src)) {
                var success = path.tryMergeLayoutForwardOnPath(exprManager);
                if (!success) {
                    pathsHasConflict.add(path);
                    path.conflict = true;
                    Logging.debug("TypeRelationPathManager", String.format("Evil in path: \n%s", path));
                }
            }
        }
    }


    /**
     * Merge paths from same source, and propagate TypeConstraints to each node start from this source.
     * This method should be called in rebuilt path manager.
     */
    public void mergePathsFromSameSource() {
        for (var src: source) {
            var mergedConstraints = new Skeleton();
            var pathsFromSource = getAllValidPathsFromSource(src);
            var success = true;
            for (var path: pathsFromSource) {
                success = mergedConstraints.tryMergeLayoutStrict(path.finalSkeletonOnPath);
                if (!success) {
                    break;
                }
            }

            if (success) {
                Logging.debug("TypeRelationPathManager", "Expected Source");
                sourceToConstraints.put(src, mergedConstraints);
                for (var path: pathsFromSource) {
                    sourceToChildren.computeIfAbsent(src, k -> new HashSet<>()).addAll(path.nodes);
                }
            } else {
                Logging.debug("TypeRelationPathManager", "Unexpected Evil Source");
                for (var path: pathsFromSource) {
                    Logging.debug("TypeRelationPathManager", path.toString());
                    Logging.debug("TypeRelationPathManager", path.finalSkeletonOnPath.dumpLayout(0));
                }
            }
        }
    }


    public void buildSkeletons(TypeHintCollector collector) {
        /* init sourceGroups */
        for (var src: source) {
            sourceGroups.add(src);
        }

        /* merge sources if they have common children nodes */
        for (var src1: source) {
            Set<T> children1 = sourceToChildren.get(src1);
            if (children1 == null) continue;

            for (T src2: source) {
                if (src1.equals(src2)) continue;

                Set<T> children2 = sourceToChildren.get(src2);
                if (children2 == null) continue;

                // if children1 and children2 has common nodes, union their sources
                for (var child1: children1) {
                    if (children2.contains(child1)) {
                        sourceGroups.union(src1, src2);
                        break;
                    }
                }
            }
        }

        var clusters = sourceGroups.getClusters();
        Logging.debug("TypeRelationPathManager", String.format("Found %d clusters in sourceGroups", clusters.size()));
        for (var cluster: clusters) {
            Logging.debug("TypeRelationPathManager", String.format("Cluster size: %s", cluster.size()));
            var layoutToSources = new HashMap<Layout, Set<T>>();
            /* group the cluster by node's layout */
            for (var src: cluster) {
                var sc = sourceToConstraints.get(src);
                if (sc == null) {
                    Logging.warn("TypeRelationPathManager", String.format("Source has no final constraints: %s", src));
                    continue;
                }
                var layout = new Layout(sc);
                layoutToSources.computeIfAbsent(layout, k -> new HashSet<>()).add(src);
            }

            if (layoutToSources.size() > 1) {
                Logging.debug("TypeRelationPathManager", "L > 1");
                /* If layout count > 1, we merge children and TC by each layout */
                for (var layout: layoutToSources.keySet()) {
                    var sources = layoutToSources.get(layout);
                    buildSkeleton(collector, sources);
                }
            } else if (layoutToSources.size() == 1) {
                /* If layout count = 1, which means all sources in this cluster have same layout, we merge them */
                Logging.debug("TypeRelationPathManager", "L = 1");
                buildSkeleton(collector, cluster);
            } else {
                Logging.error("TypeRelationPathManager", "L = 0");
            }
        }
    }

    public void buildSkeleton(TypeHintCollector collector, Set<T> sources) {
        var mergedConstraints = new Skeleton();
        for (var src: sources) {
            mergedConstraints.mergeOther(sourceToConstraints.get(src));
        }

        if (mergedConstraints.isEmpty()) { return; }

        var exprs = new HashSet<NMAE>();
        for (var src: sources) {
            var children = sourceToChildren.get(src);
            if (children == null) {
                Logging.warn("TypeRelationPathManager", String.format("Source %s has no children", src));
                continue;
            }
            for (var node: children) {
                exprs.add((NMAE) node);
            }
        }

        var skeleton = new TypeConstraint(mergedConstraints, exprs);
        collector.addSkeleton(skeleton);
    }

    /**
     * Find Source nodes in the TFG
     */
    public void findSourcesAndSinks() {
        for (T vertex : graph.getGraph().vertexSet()) {
            if (graph.getGraph().inDegreeOf(vertex) == 0 && graph.getGraph().outDegreeOf(vertex) > 0) {
                source.add(vertex);
            }
            else if (graph.getGraph().inDegreeOf(vertex) > 0 && graph.getGraph().outDegreeOf(vertex) == 0) {
                sink.add(vertex);
            }
        }
    }

    /**
     * Find all Paths from Source to Sink.
     * However, be careful that in some TFG, there has no explicit sink node or source node.
     * So our algorithm is:
     *  1. build path from sources to sinks (if they exist)
     *  2. mark all nodes in the paths
     *  3. for nodes that are not marked, start from any node and build path to any other node, record visited to avoid recursion
     *  4. Iterate using workList.
     * Be aware that alias edges are also considered as valid edges.
     *
     */
    public void findAllPathFromSrcToSink() {
        AllDirectedPaths<T, TypeFlowGraph.TypeFlowEdge> allPathsFinder = new AllDirectedPaths<>(graph.getGraph());

        for (T src : source) {
            for (T snk : sink) {
                List<GraphPath<T, TypeFlowGraph.TypeFlowEdge>> paths =
                        allPathsFinder.getAllPaths(src, snk, true, Integer.MAX_VALUE);
                for (GraphPath<T, TypeFlowGraph.TypeFlowEdge> path : paths) {
                    TypeFlowPath<T> TFPath = new TypeFlowPath<>(graph, path);
                    srcToPathsMap.computeIfAbsent(src, k -> new HashSet<>()).add(TFPath);
                }
            }
        }

        Set<T> coveredNodes = getCoveredNodes();
        Set<T> unCoveredNodes = new HashSet<>(graph.getNodes());
        unCoveredNodes.removeAll(coveredNodes);

        if (!unCoveredNodes.isEmpty()) {
            Logging.info("TypeFlowPathManager",
                    String.format("Found %d / %d nodes are uncovered by paths",
                            unCoveredNodes.size(), graph.getGraph().vertexSet().size()));

            // Find virtual sources (nodes with in-degree 0 or only connected from covered nodes)
            Set<T> virtualSources = new HashSet<>();
            // Find virtual sinks (nodes with out-degree 0 or only connected to covered nodes)
            Set<T> virtualSinks = new HashSet<>();

            for (T node : unCoveredNodes) {
                boolean isVirtualSource = true;
                boolean isVirtualSink = true;

                // Check in-edges to determine if virtual source
                for (TypeFlowGraph.TypeFlowEdge edge : graph.getGraph().incomingEdgesOf(node)) {
                    T sourceNode = graph.getGraph().getEdgeSource(edge);
                    if (unCoveredNodes.contains(sourceNode)) {
                        isVirtualSource = false;
                        break;
                    }
                }

                // Check out-edges to determine if virtual sink
                for (TypeFlowGraph.TypeFlowEdge edge : graph.getGraph().outgoingEdgesOf(node)) {
                    T targetNode = graph.getGraph().getEdgeTarget(edge);
                    if (unCoveredNodes.contains(targetNode)) {
                        isVirtualSink = false;
                        break;
                    }
                }

                if (isVirtualSource) {
                    virtualSources.add(node);
                }
                if (isVirtualSink) {
                    virtualSinks.add(node);
                }
            }

            // If no virtual sources/sinks found, pick nodes with minimum in/out degree
            if (virtualSources.isEmpty() || virtualSinks.isEmpty()) {
                T bestSource = findNodeWithMinInDegreeInSet(unCoveredNodes);
                T bestSink = findNodeWithMinOutDegreeInSet(unCoveredNodes);

                if (!virtualSources.isEmpty()) {
                    virtualSinks.add(bestSink);
                } else if (!virtualSinks.isEmpty()) {
                    virtualSources.add(bestSource);
                } else {
                    virtualSources.add(bestSource);
                    virtualSinks.add(bestSink);
                }
            }

            // Create paths between virtual sources and sinks
            for (T src : virtualSources) {
                source.add(src); // Add to global sources
                for (T snk : virtualSinks) {
                    List<GraphPath<T, TypeFlowGraph.TypeFlowEdge>> paths =
                            allPathsFinder.getAllPaths(src, snk, true, Integer.MAX_VALUE);
                    for (GraphPath<T, TypeFlowGraph.TypeFlowEdge> path : paths) {
                        TypeFlowPath<T> TFPath = new TypeFlowPath<>(graph, path);
                        srcToPathsMap.computeIfAbsent(src, k -> new HashSet<>()).add(TFPath);
                    }
                }
            }

            sink.addAll(virtualSinks);
        }
    }

    /**
     * Remove all backward edges from the graph.
     * Backward edges are defined as edges that are not part of any constructed path.
     * Anyway, these backward edges are rare.
     * from source to sink.
     */
    private void markAllBackwardEdges() {
        // Step 1: Collect all edges that are part of forward paths
        Set<TypeFlowGraph.TypeFlowEdge> forwardEdges = new HashSet<>();
        for (Set<TypeFlowPath<T>> paths : srcToPathsMap.values()) {
            for (TypeFlowPath<T> path : paths) {
                forwardEdges.addAll(path.edges);
            }
        }

        // Step 2: Get all edges from the graph
        Set<TypeFlowGraph.TypeFlowEdge> allEdges = new HashSet<>(graph.getGraph().edgeSet());

        // Step 3: Find backward edges (edges in graph but not in forward paths)
        Set<TypeFlowGraph.TypeFlowEdge> backwardEdges = new HashSet<>(allEdges);
        backwardEdges.removeAll(forwardEdges);

        // Step 4: Remove all backward edges
        if (!backwardEdges.isEmpty()) {
            Logging.info("TypeFlowPathManager",
                    String.format("Removing %d backward edges out of %d total edges",
                            backwardEdges.size(), allEdges.size()));

            // Use a new list to avoid concurrent modification
            this.backwardEdges.addAll(backwardEdges);
        }
    }

    /**
     * Get Covered nodes in the paths
     */
    private Set<T> getCoveredNodes() {
        Set<T> coveredNodes = new HashSet<>();
        for (var paths: srcToPathsMap.values()) {
            for (var path: paths) {
                coveredNodes.addAll(path.nodes);
            }
        }
        return coveredNodes;
    }

    /**
     * Find the longest common path starting from the beginning of each path
     * @param paths Set of given paths
     * @return The longest common prefix path, or an empty list if no common prefix exists
     */
    public List<T> getLongestCommonPrefixPath(Set<TypeFlowPath<T>> paths) {
        if (paths == null || paths.isEmpty()) {
            return new ArrayList<>();
        }

        // If there's only one path, the entire path is common
        if (paths.size() == 1) {
            return new ArrayList<>(paths.iterator().next().nodes);
        }

        // Get the first path as reference
        List<T> firstPath = paths.iterator().next().nodes;
        if (firstPath.isEmpty()) {
            return new ArrayList<>();
        }

        // Find minimum length among all paths
        int minLength = Integer.MAX_VALUE;
        for (TypeFlowPath<T> path : paths) {
            minLength = Math.min(minLength, path.nodes.size());
        }

        // Compare nodes at each position across all paths
        int commonLength = 0;
        for (int i = 0; i < minLength; i++) {
            T currentNode = firstPath.get(i);
            boolean allMatch = true;

            // Check if this node matches across all paths
            for (TypeFlowPath<T> path : paths) {
                if (!path.nodes.get(i).equals(currentNode)) {
                    allMatch = false;
                    break;
                }
            }

            if (allMatch) {
                commonLength++;
            } else {
                break;
            }
        }

        // Extract the common prefix if any
        if (commonLength > 0) {
            return new ArrayList<>(firstPath.subList(0, commonLength));
        }
        return new ArrayList<>();
    }

    /**
     * Get the edge at the end of the Longest Common Prefix for a specific path
     *
     * @param lcp The longest common prefix nodes
     * @param path The path to analyze
     * @return The edge connecting LCP end to the next node, or null if not found
     */
    private TypeFlowGraph.TypeFlowEdge getEndEdgeOfLCP(List<T> lcp, TypeFlowPath<T> path) {
        if (lcp == null || lcp.isEmpty() || path.nodes.size() <= lcp.size()) {
            return null;
        }

        // Check if this path starts with the LCP
        for (int i = 0; i < lcp.size(); i++) {
            if (!path.nodes.get(i).equals(lcp.get(i))) {
                return null; // Path doesn't contain LCP at the start
            }
        }

        // Return the edge connecting the last LCP node to the next node
        return path.edges.get(lcp.size() - 1);
    }

    /**
     * Get all edges within the Longest Common Prefix
     *
     * @param lcp The longest common prefix nodes
     * @param paths Set of paths to examine (only used to find one path containing the LCP)
     * @return Set of edges within the LCP
     */
    private Set<TypeFlowGraph.TypeFlowEdge> getEdgesInLCP(List<T> lcp, Set<TypeFlowPath<T>> paths) {
        Set<TypeFlowGraph.TypeFlowEdge> lcpEdges = new HashSet<>();

        if (lcp == null || lcp.size() < 2) {
            return lcpEdges; // No internal edges in empty or single-node LCP
        }

        // Find the first path containing the LCP
        for (TypeFlowPath<T> path : paths) {
            if (path.nodes.size() >= lcp.size()) {
                boolean containsLCP = true;
                for (int i = 0; i < lcp.size(); i++) {
                    if (!path.nodes.get(i).equals(lcp.get(i))) {
                        containsLCP = false;
                        break;
                    }
                }

                if (containsLCP) {
                    // Extract all edges within the LCP
                    for (int i = 0; i < lcp.size() - 1; i++) {
                        lcpEdges.add(path.edges.get(i));
                    }
                    break; // Found what we needed
                }
            }
        }

        Logging.debug("TypeFlowPathManager", "Found " + lcpEdges.size() + " edges in LCP");
        return lcpEdges;
    }

    /**
     * Split the path into 2 paths by the specified edge in the path.
     * For example:
     *  A -> B -> C -> D
     *  removedEdge : B -> C
     *  Then the path will be split into:
     *  A -> B
     *  C -> D
     */
    private Pair<TypeFlowPath<T>, TypeFlowPath<T>>
    splitPathByEdge(TypeFlowPath<T> originPath,
                    TypeFlowGraph.TypeFlowEdge removedEdge) {
        List<T> nodes = originPath.nodes;
        List<TypeFlowGraph.TypeFlowEdge> edges = originPath.edges;

        int splitIndex = -1;
        for (int i = 0; i < edges.size(); i++) {
            if (edges.get(i).equals(removedEdge)) {
                splitIndex = i;
                break;
            }
        }

        if (splitIndex == -1) {
            Logging.warn("TypeFlowPathManager", "Edge not found in path: " + removedEdge);
            return null;
        }

        List<T> prefixNodes = new ArrayList<>(nodes.subList(0, splitIndex + 1));
        List<TypeFlowGraph.TypeFlowEdge> prefixEdges = new ArrayList<>(edges.subList(0, splitIndex));
        TypeFlowPath<T> pathPrefix = new TypeFlowPath<>(graph, prefixNodes, prefixEdges);

        List<T> suffixNodes = new ArrayList<>(nodes.subList(splitIndex + 1, nodes.size()));
        List<TypeFlowGraph.TypeFlowEdge> suffixEdges = new ArrayList<>(edges.subList(splitIndex + 1, edges.size()));
        TypeFlowPath<T> pathSuffix = new TypeFlowPath<>(graph, suffixNodes, suffixEdges);

        T pathPrefixSource = pathPrefix.start;
        T pathPrefixSink = pathPrefix.end;
        T pathSuffixSource = pathSuffix.start;

        sink.add(pathPrefixSink);

        Set<TypeFlowPath<T>> paths = srcToPathsMap.get(pathPrefixSource);
        if (paths != null) {
            paths.remove(originPath);
            paths.add(pathPrefix);
        }

        source.add(pathSuffixSource);
        srcToPathsMap.computeIfAbsent(pathSuffixSource, k -> new HashSet<>()).add(pathSuffix);

        Logging.debug("TypeFlowPathManager", "Split path at edge: " + removedEdge);
        Logging.debug("TypeFlowPathManager", "Created prefix path: " + pathPrefix);
        Logging.debug("TypeFlowPathManager", "Created suffix path: " + pathSuffix);

        return new Pair<>(pathPrefix, pathSuffix);
    }

    public LinkedHashMap<Layout, Set<Skeleton>> buildLayoutToConstraints(Set<Skeleton> constraints) {
        var layoutToConstraints = new LinkedHashMap<Layout, Set<Skeleton>>();
        for (var con: constraints) {
            var layout = new Layout(con);
            layoutToConstraints.computeIfAbsent(layout, k -> new HashSet<>()).add(con);
        }
        // Ranking the layoutToConstraints by Set<TypeConstraint>.size()
        layoutToConstraints = layoutToConstraints.entrySet().stream()
                .sorted((e1, e2) -> e2.getValue().size() - e1.getValue().size())
                .collect(LinkedHashMap::new, (m, e) -> m.put(e.getKey(), e.getValue()), Map::putAll);
        return layoutToConstraints;
    }

    public Set<TypeFlowPath<T>> getAllValidPathsFromSource(T source) {
        var result = new HashSet<TypeFlowPath<T>>();
        if (!srcToPathsMap.containsKey(source)) {
            Logging.warn("TypeFlowPathManager",
                    String.format("Unexpected Source node: %s, no paths found", source));
            return result;
        }
        for (var path: srcToPathsMap.get(source)) {
            if (path.conflict) {
                Logging.warn("TypeFlowPathManager",
                        String.format("Path has conflict, not valid: %s", path));
                continue;
            }
            result.add(path);
        }
        return result;
    }

    private T findNodeWithMinInDegreeInSet(Set<T> nodeSet) {
        T result = null;
        int minDegree = Integer.MAX_VALUE;

        for (T node : nodeSet) {
            int inDegree = graph.getGraph().inDegreeOf(node);
            if (inDegree < minDegree) {
                minDegree = inDegree;
                result = node;
            }
        }

        return result;
    }

    private T findNodeWithMinOutDegreeInSet(Set<T> nodeSet) {
        T result = null;
        int minDegree = Integer.MAX_VALUE;

        for (T node : nodeSet) {
            int outDegree = graph.getGraph().outDegreeOf(node);
            if (outDegree < minDegree) {
                minDegree = outDegree;
                result = node;
            }
        }

        return result;
    }

    public void dump(FileWriter writer) throws Exception {
        writer.write(String.format("Graph: %s\n", graph));
        for (var src: source) {
            writer.write(String.format("\tSource: %s\n", src));
            var paths = srcToPathsMap.get(src);
            if (paths == null) {
                continue;
            }
            for (var path: paths) {
                writer.write(String.format("\t\t\tPath: %s\n", path));
                if (path.conflict) {
                    writer.write("\t\t\t\tConflict\n");
                } else {
                    writer.write(path.finalSkeletonOnPath.dumpLayout(4));
                }
                writer.write("\t\t\t\t======================================================\n");
            }
        }
        writer.write("\n");
    }
}
