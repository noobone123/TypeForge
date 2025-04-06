package typeforge.base.passes;

import typeforge.base.dataflow.constraint.TypeConstraint;
import typeforge.utils.Global;
import typeforge.utils.Logging;

import java.util.*;

public class SlidingWindowProcessor {
    public final TypeConstraint curSkt;
    public final List<Long> offsetList;

    private int windowCapacity;
    private int flattenCnt;

    public SlidingWindowProcessor(TypeConstraint curSkt, List<Long> offsetList, int initialWindowCapacity) {
        this.curSkt = curSkt;
        this.offsetList = offsetList;
        this.windowCapacity = initialWindowCapacity;
    }

    public Optional<Window> tryMatchingFromCurrentOffset(int curOffsetIndex, final int threshold) {
        Optional<Window> windowOpt = getWindowAtOffset(curOffsetIndex);
        if (windowOpt.isEmpty()) {
            return Optional.empty();
        }

        var window = windowOpt.get();
        int matchCount = 1;
        int alignedWindowSize = window.getAlignedWindowSize();
        long prevWindowStartOffset = offsetList.get(curOffsetIndex);
        var prevWindow = window;

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
                    prevWindow = candidateWindow;
                } else {
                    Logging.debug("SlidingWindowProcessor", "Window equal but not contiguous of Skeleton " + curSkt);
                    Logging.debug("SlidingWindowProcessor",
                            String.format("Previous Window:\nStart: 0x%x\n%s", prevWindowStartOffset, prevWindow));
                    Logging.debug("SlidingWindowProcessor",
                            String.format("Current Window:\nStart: 0x%x\n%s", offsetList.get(i), candidateWindow));
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

    public void setWindowCapacity(int newWindowCapacity) {
        this.windowCapacity = newWindowCapacity;
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

        var startOffset = offsetList.get(startIndex);

        /* We don't consider windows with only one element if the element is a pointer */
        if (windowCapacity == 1 &&
                (curSkt.innerSkeleton.fieldAccess.get(startOffset).mostAccessedDT.getLength() == Global.currentProgram.getDefaultPointerSize())) {
            return Optional.empty();
        }

        var window = new Window();

        long prevOffset = -1;

        for (int i = 0; i < windowCapacity; i++) {
            var currentOffset = offsetList.get(startIndex + i);
            if (curSkt.isInconsistentOffset(currentOffset)) {
                return Optional.empty();
            }
            if (curSkt.hasNestedConstraint() && curSkt.isInNestedRange(currentOffset)) {
                return Optional.empty();
            }

            Object element = null;
            if (curSkt.finalPtrReference.containsKey(currentOffset)) {
                element = curSkt.finalPtrReference.get(currentOffset);
            } else {
                element = curSkt.innerSkeleton.fieldAccess.get(currentOffset);
            }

            var relativeOffset = currentOffset.intValue() - startOffset.intValue();
            window.addElement(relativeOffset, element);
            if (element instanceof TypeConstraint) {
                window.addPtrLevel(relativeOffset, curSkt.ptrLevel.get(currentOffset) != null ? curSkt.ptrLevel.get(currentOffset) : 1);
            }

            prevOffset = currentOffset;
        }

        /* Check if all the elements in the window are of the same type (excluded capacity 1) */
        if (window.isHomogeneous() || (!window.isContiguous())) {
            return Optional.empty();
        }

        return Optional.of(window);
    }
}
