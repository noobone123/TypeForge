package typeforge.base.dataflow.TFG;

import typeforge.base.dataflow.expression.NMAE;
import typeforge.base.dataflow.expression.NMAEManager;
import typeforge.base.dataflow.UnionFind;
import typeforge.base.dataflow.constraint.TypeConstraint;
import typeforge.base.dataflow.constraint.TypeHintCollector;
import typeforge.base.dataflow.constraint.Skeleton;
import typeforge.base.dataflow.Layout;
import typeforge.utils.Logging;
import ghidra.program.model.listing.Function;
import org.jgrapht.alg.shortestpath.AllDirectedPaths;

import java.io.FileWriter;
import java.util.*;

public class TypeRelationPathManager<T> {
    public TypeFlowGraph<T> graph;
    public boolean hasSrcSink = true;
    public final Set<T> source;
    public final Set<T> sink;

    public final Map<T, Set<TypeRelationPath<T>>> nodeToPathsMap;
    public final Map<T, Set<TypeRelationPath<T>>> srcToPathsMap;

    public final Map<T, Set<Skeleton>> nodeToConstraints;

    /** fields for handle conflict paths and nodes */
    public final Set<TypeRelationPath<T>> evilPaths = new HashSet<>();  /** EvilPaths are paths that may cause type ambiguity */
    public final Set<T> evilNodes = new HashSet<>();  /* EvilNodes are nodes that may cause type ambiguity */
    public final Map<T, Set<TypeFlowGraph.TypeFlowEdge>> evilNodeEdges = new HashMap<>();
    public final Set<T> evilSource = new HashSet<>();
    public final Set<Function> evilFunction = new HashSet<>();
    public final Map<T, Set<TypeFlowGraph.TypeFlowEdge>> evilSourceLCSEdges = new HashMap<>();
    public final Map<T, Set<TypeFlowGraph.TypeFlowEdge>> evilSourceEndEdges = new HashMap<>();

    /** fields for handle edges that introduce conflicts */
    public final Set<TypeFlowGraph.TypeFlowEdge> mustRemove = new HashSet<>();
    public final Set<TypeFlowGraph.TypeFlowEdge> mayRemove = new HashSet<>();
    public final Set<TypeFlowGraph.TypeFlowEdge> keepEdges = new HashSet<>();

    /** Fields for build skeletons, not used for conflict checking
     * If source's PathNodes has common nodes, we should put them in one cluster using UnionFind */
    public UnionFind<T> sourceGroups = new UnionFind<>();
    public final Map<T, Set<T>> sourceToChildren = new HashMap<>();
    public final Map<T, Skeleton> sourceToConstraints = new HashMap<>();

    public TypeRelationPathManager(TypeFlowGraph<T> graph) {
        this.graph = graph;
        this.source = new HashSet<>();
        this.sink = new HashSet<>();
        this.nodeToPathsMap = new HashMap<>();
        this.srcToPathsMap = new HashMap<>();
        this.nodeToConstraints = new HashMap<>();
    }

    public void build() {
        this.source.clear();
        this.sink.clear();
        this.nodeToPathsMap.clear();
        this.srcToPathsMap.clear();
        this.nodeToConstraints.clear();

        findSources();
        findSinks();
        if (source.isEmpty() || sink.isEmpty()) {
            hasSrcSink = false;
            return;
        }

        if (hasSrcSink) {
            findAllPathFromSrcToSink();
        }

        for (var src: srcToPathsMap.keySet()) {
            for (var path: srcToPathsMap.get(src)) {
                updateNodeToPathsMap(path);
            }
        }
    }

    /**
     * Try merge TypeConstraints using nodes in one path
     * IMPORTANT: This Function should be called after all Graph's pathManager built
     */
    public void tryMergeOnPath(NMAEManager exprManager) {
        for (var src: srcToPathsMap.keySet()) {
            for (var path: srcToPathsMap.get(src)) {
                Logging.debug("TypeRelationPathManager", "============================================== start ==============================================\n");
                Logging.debug("TypeRelationPathManager", String.format("Try merge by path: %s", path));
                var success = path.tryMergeOnPath(exprManager);
                if (!success) {
                    evilPaths.add(path);
                    path.evil = true;
                    Logging.debug("TypeRelationPathManager", String.format("Conflict found in path: \n%s", path));
                } else {
                    if (path.finalConstraint.isEmpty()) {
                        path.noComposite = true;
                    }
                }
                Logging.debug("TypeRelationPathManager", "============================================== end ==============================================\n");
            }
        }
    }

    // Try merge paths from same source, them propagate TypeConstraints to each node start from this source
    // Because there may have some node with paths from different source, we then handle them in next step
    public void tryMergePathsFromSameSource(NMAEManager exprManager) {
        var workList = new LinkedList<T>(source);

        while (!workList.isEmpty()) {
            var src = workList.poll();
            var mergedCon = new Skeleton();
            var pathsFromSrc = getAllValidPathsFromSource(src);
            if (pathsFromSrc.isEmpty()) {
                Logging.warn("TypeRelationPathManager", String.format("No valid paths from source %s", src));
                continue;
            }

            var success = true;
            for (var path: pathsFromSrc) {
                success = mergedCon.tryMerge(path.finalConstraint);
                if (!success) {
                    break;
                }
            }

            // If there has conflict when merging different paths from same source, means there maybe wrapper function or some other reasons
            // For soundness, we need to find the longest common subpath in these paths and remove edges
            if (!success) {
                /* Mark all exprs connect to this source in current function as evil */
                evilSource.add(src);
                evilFunction.add(((NMAE)src).function);
                Logging.debug("TypeRelationPathManager", String.format("Evil source nodes found: %s", src));
                Logging.warn("TypeRelationPathManager", String.format("Evil function found: %s", ((NMAE)src).function));
                for (var path: pathsFromSrc) {
                    Logging.debug("TypeRelationPathManager", path.toString());
                }

                var LCSs = getLongestCommonSubpath(pathsFromSrc);
                List<T> wrapperPath = new ArrayList<>();
                for (var lcs: LCSs) {
                    if (lcs.contains(src)) {
                        wrapperPath = lcs;
                    }
                }
                Logging.debug("TypeRelationPathManager", String.format("Wrapper Path: %s", wrapperPath));
                var endEdges = getEndEdgesOfLCS(wrapperPath, pathsFromSrc);
                var lcsEdges = getEdgesInLCS(wrapperPath, pathsFromSrc);
                evilSourceEndEdges.put(src, endEdges);
                evilSourceLCSEdges.put(src, lcsEdges);

                /* wrapperPath's end edges mark must remove */
                mustRemove.addAll(endEdges);
                keepEdges.addAll(lcsEdges);
                /* Split Paths from Source by end Edges, And Created New Paths */
                var newPaths = splitPathsByLCS(pathsFromSrc, endEdges, exprManager);

                /* update metadata using newPaths */
                for (var path: pathsFromSrc) {
                    source.remove(path.start);
                    srcToPathsMap.remove(path.start);
                    for (var node: path.nodes) {
                        nodeToPathsMap.get(node).remove(path);
                    }
                }

                var newSources = new HashSet<T>();
                for (var path: newPaths) {
                    newSources.add(path.start);
                    source.add(path.start);
                    srcToPathsMap.computeIfAbsent(path.start, k -> new HashSet<>()).add(path);
                    for (var node: path.nodes) {
                        nodeToPathsMap.computeIfAbsent(node, k -> new HashSet<>()).add(path);
                    }
                }
                workList.addAll(newSources);
            }

            // If there has no conflict when merging different paths from same source, we propagate the merged Constraints
            // to each node start from this source
            else {
                Logging.debug("TypeRelationPathManager", String.format("No Conflict when merging paths from same source: %s", src));
                for (var path: pathsFromSrc) {
                    if (path.evil || path.noComposite) {
                        continue;
                    }
                    propagateConstraintOnPath(mergedCon, path);
                }
            }
        }
    }

    /**
     * If there has multiple TypeConstraints in one node, means there has TypeConstraints
     * from different sources, we should handle them and try to merge them.
     */
    public void tryHandleConflictNodes() {
        for (var node: nodeToConstraints.keySet()) {
            var constraints = nodeToConstraints.get(node);
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
                        success = mergedConstraints.tryMerge(con);
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
                        for (var path: nodeToPathsMap.get(node)) {
                            if (path.evil || path.noComposite) {
                                continue;
                            }
                            Logging.debug("TypeRelationPathManager", path.toString());
                        }
                        /* End Debugging */

                        evilNodeEdges.put(node, new HashSet<>(graph.getGraph().edgesOf(node)));
                        /* If there has LCS in node's paths, we should keep edges in LCS */
                        var LCSs = getLongestCommonSubpath(nodeToPathsMap.get(node));
                        for (var lcs: LCSs) {
                            var lcsEdges = getEdgesInLCS(lcs, nodeToPathsMap.get(node));
                            keepEdges.addAll(lcsEdges);
                        }
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

        var removedEdges = new HashSet<>(mustRemove);
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
                var success = path.tryMergeOnPath(exprManager);
                if (!success) {
                    evilPaths.add(path);
                    path.evil = true;
                    Logging.debug("TypeRelationPathManager", String.format("Evil in path: \n%s", path));
                } else {
                    if (path.finalConstraint.isEmpty()) {
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
                success = mergedConstraints.tryMerge(path.finalConstraint);
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
                    Logging.debug("TypeRelationPathManager", path.finalConstraint.dumpLayout(0));
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


    public void findSources() {
        for (T vertex : graph.getGraph().vertexSet()) {
            if (graph.getGraph().inDegreeOf(vertex) == 0 && graph.getGraph().outDegreeOf(vertex) > 0) {
                source.add(vertex);
            }
        }
    }

    public void findSinks() {
        for (T vertex : graph.getGraph().vertexSet()) {
            if (graph.getGraph().inDegreeOf(vertex) > 0 && graph.getGraph().outDegreeOf(vertex) == 0) {
                sink.add(vertex);
            }
        }
    }

    public void findAllPathFromSrcToSink() {
        for (T src: source) {
            for (T sk: sink) {
                var allPaths = new AllDirectedPaths<>(graph.getGraph()).getAllPaths(src, sk, true, Integer.MAX_VALUE);
                for (var path: allPaths) {
                    TypeRelationPath<T> typeRelationPath = new TypeRelationPath<>(path);
                    srcToPathsMap.computeIfAbsent(src, k -> new HashSet<>()).add(typeRelationPath);
                }
            }
        }
    }

    /**
     * Get the longest common path in given paths using binary search and sub-path's hash ...
     * @param paths Set of given paths
     * @return Set of sub-paths
     */
    public Set<List<T>> getLongestCommonSubpath(Set<TypeRelationPath<T>> paths) {
        int lowBound = 1;
        int highBound = Integer.MAX_VALUE;
        Map<Integer, Set<Integer>> lengthToPathHash = new HashMap<>();
        for (var path: paths) {
            highBound = Math.min(highBound, path.nodes.size());
        }

        while (lowBound <= highBound) {
            int length = (lowBound + highBound) / 2;

            // get all sub-paths with length
            for (var path: paths) {
                path.createSubPathsOfLength(length);
            }

            // check all paths if there has common sub-path by intersecting their sub-paths hash
            var firstPath = paths.iterator().next();
            var firstPathHashes = firstPath.subPathsOfLengthWithHash.get(length).keySet();
            for (var p: paths) {
                var pathHashes = p.subPathsOfLengthWithHash.get(length).keySet();
                firstPathHashes.retainAll(pathHashes);
            }

            if (firstPathHashes.isEmpty()) {
                highBound = length - 1;
            } else {
                lowBound = length + 1;
                lengthToPathHash.put(length, firstPathHashes);
            }
        }

        // get the longest common path in lengthToPathHash
        int maxLength = 0;
        for (var length: lengthToPathHash.keySet()) {
            if (length > maxLength) {
                maxLength = length;
            }
        }

        var maxLengthsHashes = lengthToPathHash.get(maxLength);
        var firstPath = paths.iterator().next();


        var result = new HashSet<List<T>>();
        for (var hash: maxLengthsHashes) {
            var subPathNodes = firstPath.subPathsOfLengthWithHash.get(maxLength).get(hash);
            if (subPathNodes != null) {
                result.add(subPathNodes);
                Logging.debug("TypeRelationPathManager", String.format("Found common path: %s", subPathNodes));
            }
        }

        return result;
    }


    /**
     * Obtain the edges located at ends of the given LCS (Longest Common Subpath) in the set of paths.
     * @param lcs given Longest Common Subpath in the set of paths
     * @param paths set of paths
     */
    private Set<TypeFlowGraph.TypeFlowEdge> getEndEdgesOfLCS(List<T> lcs, Set<TypeRelationPath<T>> paths) {
        Set<TypeFlowGraph.TypeFlowEdge> endEdges = new HashSet<>();
        if (lcs.isEmpty()) {
            return endEdges;
        }

        for (var path: paths) {
            List<T> nodes = path.nodes;
            List<TypeFlowGraph.TypeFlowEdge> edges = path.edges;

            // Find the start index of the LCS in the current path
            int startIdx = Collections.indexOfSubList(nodes, lcs);
            if (startIdx == -1) {
                continue;
            }

            // Find the ending index of the LCS in the current path
            int endIdx = startIdx + lcs.size() - 1;

            // Get the edge at the end of the LCS
            if (endIdx < edges.size()) {
                endEdges.add(edges.get(endIdx));
            }
        }

        for (var edge: endEdges) {
            Logging.debug("TypeRelationPathManager", String.format("End Edge of LCS: %s", edge));
        }

        return endEdges;
    }


    private Set<TypeFlowGraph.TypeFlowEdge> getEdgesInLCS(List<T> lcs, Set<TypeRelationPath<T>> paths) {
        // Initialize a set to store the edges within the LCS
        Set<TypeFlowGraph.TypeFlowEdge> lcsEdges = new HashSet<>();

        // Loop through each path in the set
        for (TypeRelationPath<T> path : paths) {
            List<T> nodes = path.nodes;
            List<TypeFlowGraph.TypeFlowEdge> edges = path.edges;

            // Find the starting index of LCS in the current path
            int startIdx = Collections.indexOfSubList(nodes, lcs);
            if (startIdx == -1) {
                // LCS not found in this path, continue to the next path
                continue;
            }

            // Find the ending index of LCS in the current path
            int endIdx = startIdx + lcs.size() - 1;

            // Collect the edges corresponding to the LCS
            for (int i = startIdx; i < endIdx; i++) {
                lcsEdges.add(edges.get(i));
            }
        }

        for (var edge: lcsEdges) {
            Logging.debug("TypeRelationPathManager", String.format("Edges in LCS: %s", edge));
        }

        return lcsEdges;
    }

    private Set<TypeRelationPath<T>> splitPathsByLCS(Set<TypeRelationPath<T>> candidatePaths,
                                                     Set<TypeFlowGraph.TypeFlowEdge> endEdgesOfLCS,
                                                     NMAEManager exprManager) {
        Set<TypeRelationPath<T>> newPaths = new HashSet<>();

        for (TypeRelationPath<T> path : candidatePaths) {
            List<T> nodes = path.nodes;
            List<TypeFlowGraph.TypeFlowEdge> edges = path.edges;

            var splitIndex = 0;
            for (int i = 0; i < edges.size(); i++) {
                if (endEdgesOfLCS.contains(edges.get(i))) {
                    List<T> subPathNodes = new ArrayList<>(nodes.subList(0, i + 1));
                    List<TypeFlowGraph.TypeFlowEdge> subPathEdges = new ArrayList<>(edges.subList(0, i));

                    if (!subPathNodes.isEmpty()) {
                        TypeRelationPath<T> newPath = new TypeRelationPath<>(subPathNodes, subPathEdges);
                        newPaths.add(newPath);
                    }

                    splitIndex = i + 1;
                    break;
                }
            }

            // Add the remaining part of the path as a new path if any
            if (splitIndex < nodes.size()) {
                List<T> remainingNodes = new ArrayList<>(nodes.subList(splitIndex, nodes.size()));
                List<TypeFlowGraph.TypeFlowEdge> remainingEdges = new ArrayList<>(edges.subList(splitIndex, edges.size()));

                if (!remainingNodes.isEmpty()) {
                    TypeRelationPath<T> newPath = new TypeRelationPath<>(remainingNodes, remainingEdges);
                    newPaths.add(newPath);
                }
            }
        }

        for (var path: newPaths) {
            var success = path.tryMergeOnPath(exprManager);
            if (!success) {
                path.evil = true;
            }
            if (path.finalConstraint.isEmpty()) {
                path.noComposite = true;
            }
            Logging.debug("TypeRelationPathManager", String.format("New Path split by LCS:\n%s", path));
        }

        return newPaths;
    }


    public void updateNodeToPathsMap(TypeRelationPath<T> path) {
        for (var node: path.nodes) {
            nodeToPathsMap.computeIfAbsent(node, k -> new HashSet<>()).add(path);
        }
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


    public Set<TypeRelationPath<T>> getAllValidPathsFromSource(T source) {
        var result = new HashSet<TypeRelationPath<T>>();
        if (!srcToPathsMap.containsKey(source)) {
            return result;
        }
        for (var path: srcToPathsMap.get(source)) {
            if (path.evil || path.noComposite) {
                continue;
            }
            result.add(path);
        }
        return result;
    }

    public void propagateConstraintOnPath(Skeleton constraint, TypeRelationPath<T> path) {
        for (var node: path.nodes) {
            nodeToConstraints.computeIfAbsent(node, k -> new HashSet<>()).add(constraint);
        }
    }

    public Set<TypeRelationPath<T>> getAllPathContainsNode(T node) {
        return nodeToPathsMap.get(node);
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
                if (path.evil) {
                    writer.write("\t\t\t\tConflict\n");
                } else if (path.noComposite) {
                    writer.write("\t\t\t\tNo Composite\n");
                } else {
                    writer.write(path.finalConstraint.dumpLayout(4));
                }
                writer.write("\t\t\t\t======================================================\n");
            }
        }
        writer.write("\n");
    }
}
