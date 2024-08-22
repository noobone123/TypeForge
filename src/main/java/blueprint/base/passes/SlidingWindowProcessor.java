package blueprint.base.passes;

import blueprint.base.dataflow.AccessPoints;
import blueprint.base.dataflow.skeleton.Skeleton;
import blueprint.utils.Global;
import blueprint.utils.Logging;
import ghidra.program.model.data.DataType;

import java.util.*;

public class SlidingWindowProcessor {
    public final Skeleton curSkt;
    public final List<Long> offsetList;

    private int windowCapacity;
    private int flattenCnt;

    public SlidingWindowProcessor(Skeleton curSkt, List<Long> offsetList, int initialWindowCapacity) {
        this.curSkt = curSkt;
        this.offsetList = offsetList;
        this.windowCapacity = initialWindowCapacity;
    }

    public Optional<Window> tryMatchingFromCurrentOffset(int curOffsetIndex) {
        Optional<Window> windowOpt = getWindowAtOffset(curOffsetIndex);
        if (windowOpt.isEmpty()) {
            return Optional.empty();
        }

        var window = windowOpt.get();
        final int threshold = 4;
        int matchCount = 1;
        int alignedWindowSize = window.getAlignedWindowSize();
        long prevWindowStartOffset = offsetList.get(curOffsetIndex);

        for (int i = curOffsetIndex + windowCapacity; i < offsetList.size(); i += windowCapacity) {
            Optional<Window> candidateWindowOpt = getWindowAtOffset(i);
            if (candidateWindowOpt.isEmpty()) {
                break;
            }

            var candidateWindow = candidateWindowOpt.get();
            if (window.equals(candidateWindow)) {
                if ((offsetList.get(i) - prevWindowStartOffset) == alignedWindowSize) {
                    matchCount++;
                    prevWindowStartOffset = offsetList.get(i);
                } else {
                    Logging.info("SlidingWindowProcessor",
                            String.format("Window equal but not contiguous: \n Window: %s\n Aligned Size: %d\n PrevWindowStart: %s, CurrentWindowStart: %s",
                                    window, alignedWindowSize, prevWindowStartOffset, offsetList.get(i)));
                    break;
                }
            } else {
                break;
            }
        }

        if (matchCount >= threshold) {
            flattenCnt = matchCount;
            return Optional.of(window);
        } else {
            return Optional.empty();
        }
    }

    public void setWindowSize(int newWindowSize) {
        this.windowCapacity = newWindowSize;
    }

    public void resetFlattenCnt() {
        flattenCnt = 0;
    }

    public int getFlattenCount() {
        return flattenCnt;
    }

    private Optional<Window> getWindowAtOffset(int startIndex) {
        if (startIndex + windowCapacity > offsetList.size()) {
            return Optional.empty();
        }

        var window = new Window();

        long prevOffset = -1;
        var startOffset = offsetList.get(startIndex);

        if (windowCapacity == 1 &&
                (curSkt.finalConstraint.fieldAccess.get(startOffset).mostAccessedDT.getLength() == Global.currentProgram.getDefaultPointerSize())) {
            return Optional.empty();
        }

        for (int i = 0; i < windowCapacity; i++) {
            var currentOffset = offsetList.get(startIndex + i);
            if (curSkt.isInconsistentOffset(currentOffset)) {
                return Optional.empty();
            }

            Object element = null;
            if (curSkt.finalPtrReference.containsKey(currentOffset)) {
                element = curSkt.finalPtrReference.get(currentOffset);
            } else {
                element = curSkt.finalConstraint.fieldAccess.get(currentOffset);
            }

            if (prevOffset != -1 && !isContiguous(prevOffset, currentOffset, element)) {
                return Optional.empty();
            }

            var relativeOffset = currentOffset.intValue() - startOffset.intValue();
            window.addElement(relativeOffset, element);
            if (element instanceof Skeleton) {
                window.addPtrLevel(relativeOffset, curSkt.ptrLevel.get(currentOffset));
            }

            prevOffset = currentOffset;
        }
        return Optional.of(window);
    }

    private boolean isContiguous(long prevOffset, long curOffset, Object element) {
        long size;
        if (element instanceof Skeleton) {
            size = Global.currentProgram.getDefaultPointerSize();
        } else if (element instanceof AccessPoints.APSet apset) {
            size = apset.mostAccessedDT.getLength();
        } else {
            return false;
        }

        return prevOffset >= (curOffset - size) && prevOffset < curOffset;
    }
}
