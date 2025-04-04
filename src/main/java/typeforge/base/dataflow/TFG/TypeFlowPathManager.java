package typeforge.base.dataflow.TFG;

import generic.stl.Pair;
import typeforge.base.dataflow.expression.NMAE;
import typeforge.base.dataflow.expression.NMAEManager;
import typeforge.base.dataflow.UnionFind;
import typeforge.base.dataflow.constraint.TypeConstraint;
import typeforge.base.dataflow.solver.TypeHintCollector;
import typeforge.base.dataflow.constraint.Skeleton;
import typeforge.base.dataflow.Layout;
import typeforge.utils.Logging;
import ghidra.program.model.listing.Function;
import org.jgrapht.alg.shortestpath.AllDirectedPaths;

import java.io.FileWriter;
import java.util.*;

public class TypeFlowPathManager<T> {
    public TypeFlowGraph<T> graph;
    public boolean hasSrcSink = true;

    /** Import metadata for TypeFlowPathManager, should be updated when graph changed */
    public final Set<T> source;
    public final Set<T> sink;
    public final Map<T, Set<TypeFlowPath<T>>> srcToPathsMap;
    public final Map<T, Skeleton> srcToMergedSkeleton;

    /** node to Skeletons when propagating layout information BFS */
    public final Map<T, Set<Skeleton>> nodeToSkeletons;

    /** fields for handle conflict paths and nodes */
    public final Set<TypeFlowPath<T>> pathsHasConflict = new HashSet<>();
    public final Set<T> evilNodes = new HashSet<>();
    public final Map<T, Set<TypeFlowGraph.TypeFlowEdge>> evilNodeEdges = new HashMap<>();
    public final Set<T> conflictSources = new HashSet<>();
    public final Set<Function> evilFunction = new HashSet<>();
    public final Map<T, Set<TypeFlowGraph.TypeFlowEdge>> evilSourceLCSEdges = new HashMap<>();
    public final Map<T, Set<TypeFlowGraph.TypeFlowEdge>> evilSourceEndEdges = new HashMap<>();

    /** fields for handle edges that introduce conflicts */
    public final Set<Pair<T, T>> evilEdgesInPerPath = new HashSet<>();
    public final Set<TypeFlowGraph.TypeFlowEdge> evilEdgesInSourceAggregate = new HashSet<>();
    public final Set<TypeFlowGraph.TypeFlowEdge> mayRemove = new HashSet<>();
    public final Set<TypeFlowGraph.TypeFlowEdge> keepEdges = new HashSet<>();

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
        this.nodeToSkeletons = new HashMap<>();
    }

    public void initialize() {
        Logging.debug("TypeFlowPathManager",
                String.format("Initialize TypeFlowPathManager for graph: %s", graph));

        this.source.clear();
        this.sink.clear();
        this.srcToPathsMap.clear();
        this.srcToMergedSkeleton.clear();
        this.nodeToSkeletons.clear();

        findSources();
        findSinks();
        if (source.isEmpty() || sink.isEmpty()) {
            hasSrcSink = false;
            return;
        }

        if (hasSrcSink) {
            findAllPathFromSrcToSink();
        }
    }

    /**
     * Try merge Skeletons from each node along the same path
     * IMPORTANT: This Function should be called after all Graph's pathManager built
     */
    public void tryMergeLayoutFormSamePaths(NMAEManager exprManager) {
        Queue<TypeFlowPath<T>> workList = new LinkedList<>();

        // First phase: check all paths for conflicts
        for (var src: srcToPathsMap.keySet()) {
            for (var path: srcToPathsMap.get(src)) {
                var success = path.tryMergeLayoutForwardOnPath(exprManager);
                if (!success) {
                    pathsHasConflict.add(path);
                    evilEdgesInPerPath.add(path.conflictEdge);
                    path.conflict = true;
                    workList.add(path);
                } else {
                    if (path.finalSkeletonOnPath.isEmpty()) {
                        path.noComposite = true;
                    }
                }
            }
        }

        // Second phase: recursively process conflict paths using workList
        while (!workList.isEmpty()) {
            var path = workList.poll();
            if (!path.conflict || path.conflictEdge == null) continue;

            var conflictEdge = graph.getGraph().getEdge(path.conflictEdge.first, path.conflictEdge.second);
            // Metadata will be updated in splitPathByEdge
            var newPaths = splitPathByEdge(path, conflictEdge);
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
            } else {
                if (pathPrefix.finalSkeletonOnPath.isEmpty()) {
                    pathPrefix.noComposite = true;
                }
            }

            // Process suffix path
            var suffixSuccess = pathSuffix.tryMergeLayoutForwardOnPath(exprManager);
            if (!suffixSuccess) {
                pathsHasConflict.add(pathSuffix);
                pathSuffix.conflict = true;
                evilEdgesInPerPath.add(pathSuffix.conflictEdge);
                workList.add(pathSuffix); // Add back to workList for further processing
            } else {
                if (pathSuffix.finalSkeletonOnPath.isEmpty()) {
                    pathSuffix.noComposite = true;
                }
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
    public void tryMergeLayoutFromSameSource(NMAEManager exprManager) {
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
                success = mergedSkt.tryMergeLayout(path.finalSkeletonOnPath);
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
                    if (pathPrefix.finalSkeletonOnPath.isEmpty()) {
                        pathPrefix.noComposite = true;
                    }
                    if (pathSuffix.finalSkeletonOnPath.isEmpty()) {
                        pathSuffix.noComposite = true;
                    }

                    workList.add(pathPrefix.start);
                    workList.add(pathSuffix.start);
                }
            }
        }
    }

    /**
     * If there has multiple TypeConstraints in one node, means there has TypeConstraints
     * from different sources, we should handle them and try to merge them.
     */
    public void tryHandleConflictNodes() {
        for (var node: nodeToSkeletons.keySet()) {
            var constraints = nodeToSkeletons.get(node);
            if (constraints.size() > 1) {
                // Two Problem to solve:
                // 1. How to find which nodes need to remove edge
                // 2. which edge to remove: all edge? backward edges? forward edges?
                // 3. which type of edge to remove? CALL? DATAFLOW? or ...
                var layoutToConstraints = buildLayoutToConstraints(constraints);

                if (layoutToConstraints.size() > 1) {
                    Logging.debug("TypeRelationPathManager", String.format("Node has multiple Layouts: %s: %d", node, layoutToConstraints.size()));

                    var success = true;
                    var mergedConstraints = new Skeleton();
                    for (var con: constraints) {
                        success = mergedConstraints.tryMergeLayout(con);
                        if (!success) { break; }
                    }

                    if (!success) {
                        Logging.warn("TypeRelationPathManager", String.format("Evil nodes found: %s", node));
                        evilNodes.add(node);
                        evilFunction.add(((NMAE)node).function);

                        /* Start debugging */
                        for (var layout: layoutToConstraints.keySet()) {
                            Logging.debug("TypeRelationPathManager", String.format("Layout count: %d", layoutToConstraints.get(layout).size()));
                            Logging.debug("TypeRelationPathManager", layoutToConstraints.get(layout).iterator().next().dumpLayout(0));
                        }

//                        for (var path: nodeToPathsMap.get(node)) {
//                            if (path.conflict || path.noComposite) {
//                                continue;
//                            }
//                            Logging.debug("TypeRelationPathManager", path.toString());
//                        }
//                        /* End Debugging */
//
//                        evilNodeEdges.put(node, new HashSet<>(graph.getGraph().edgesOf(node)));
//                        /* If there has LCS in node's paths, we should keep edges in LCS */
//                        var LCSs = getLongestCommonSubpath(nodeToPathsMap.get(node));
//                        for (var lcs: LCSs) {
//                            var lcsEdges = getEdgesInLCS(lcs, nodeToPathsMap.get(node));
//                            keepEdges.addAll(lcsEdges);
//                        }
                    }
                }
                else if (layoutToConstraints.size() == 1) {
                    Logging.warn("TypeRelationPathManager", "Only one layout found in node's constraints, no conflict confirmed");
                }
                else {
                    Logging.warn("TypeRelationPathManager", "No layout found in node's constraints");
                }
            }
            else {
                Logging.debug("TypeRelationPathManager", String.format("Node has single TypeConstraints: %s: %d", node, constraints.size()));
            }
        }
    }

    /**
     * Removed edges are mustRemove + (mayRemove - keepEdges)
     */
    public Set<TypeFlowGraph.TypeFlowEdge> getEdgesToRemove() {
        /* Add all edges of current conflict node to mustRemove */
        for (var node: evilNodes) {
            mayRemove.addAll(graph.getGraph().edgesOf(node));
        }

        var removedEdges = new HashSet<>(evilEdgesInSourceAggregate);
        for (var edge: mayRemove) {
            if (!keepEdges.contains(edge)) {
                removedEdges.add(edge);
                Logging.debug("TypeRelationPathManager", String.format("Mark Edge to remove: %s", edge));
            }
        }
        return removedEdges;
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
                } else {
                    if (path.finalSkeletonOnPath.isEmpty()) {
                        path.noComposite = true;
                        continue;
                    }
                    Logging.debug("TypeRelationPathManager", String.format("Expected path: \n%s", path));
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
                success = mergedConstraints.tryMergeLayout(path.finalSkeletonOnPath);
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
    public void findSources() {
        for (T vertex : graph.getGraph().vertexSet()) {
            if (graph.getGraph().inDegreeOf(vertex) == 0 && graph.getGraph().outDegreeOf(vertex) > 0) {
                source.add(vertex);
            }
        }
    }

    /**
     * Find Sink nodes in the TFG
     */
    public void findSinks() {
        for (T vertex : graph.getGraph().vertexSet()) {
            if (graph.getGraph().inDegreeOf(vertex) > 0 && graph.getGraph().outDegreeOf(vertex) == 0) {
                sink.add(vertex);
            }
        }
    }

    /**
     * Be aware that alias edges are also considered as valid edges
     */
    public void findAllPathFromSrcToSink() {
        for (T src: source) {
            for (T sk: sink) {
                var allPaths = new AllDirectedPaths<>(graph.getGraph()).getAllPaths(src, sk, true, Integer.MAX_VALUE);
                for (var path: allPaths) {
                    TypeFlowPath<T> typeFlowPath = new TypeFlowPath<>(path);
                    srcToPathsMap.computeIfAbsent(src, k -> new HashSet<>()).add(typeFlowPath);
                }
            }
        }
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
        TypeFlowPath<T> pathPrefix = new TypeFlowPath<>(prefixNodes, prefixEdges);

        List<T> suffixNodes = new ArrayList<>(nodes.subList(splitIndex + 1, nodes.size()));
        List<TypeFlowGraph.TypeFlowEdge> suffixEdges = new ArrayList<>(edges.subList(splitIndex + 1, edges.size()));
        TypeFlowPath<T> pathSuffix = new TypeFlowPath<>(suffixNodes, suffixEdges);

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
            return result;
        }
        for (var path: srcToPathsMap.get(source)) {
            if (path.conflict || path.noComposite) {
                continue;
            }
            result.add(path);
        }
        return result;
    }

    public void propagateSkeletonsOnPath(Skeleton constraint, TypeFlowPath<T> path) {
        for (var node: path.nodes) {
            nodeToSkeletons.computeIfAbsent(node, k -> new HashSet<>()).add(constraint);
        }
    }

    public void dump(FileWriter writer) throws Exception {
        if (!hasSrcSink) {
            return;
        }
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
                } else if (path.noComposite) {
                    writer.write("\t\t\t\tNo Composite\n");
                } else {
                    writer.write(path.finalSkeletonOnPath.dumpLayout(4));
                }
                writer.write("\t\t\t\t======================================================\n");
            }
        }
        writer.write("\n");
    }
}
