using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.Pipeline {
    public class StageList : IEnumerable<PipelineStage> {
        public StageList(PipelineStage initial) {
            this.Stages = new List<PipelineStage>();
            AddStage(initial);
        }
        internal void AddStage(PipelineStage stage) {
            this.Stages.Add(stage);
        }

        public bool HasProcessor<T>() where T : Processor {
            foreach (var s in this) {
                var ps = s as IHasProcessor;
                if (ps != null) {
                    if (ps.Processor is T)
                        return true;
                }
            }
            return false;
        }

        public void Replace<T>(Processor newProcessor) where T : Processor {
            foreach (var stage in this) {
                var processorStage = stage as IHasProcessor;
                if (processorStage != null) {
                    if (processorStage.Processor is T)
                        processorStage.Processor = newProcessor;
                }
            }
        }
        public void Replace<T, TPIn, TPOut>(Func<TPIn, TPOut> conversion) where T : Processor<TPIn, TPOut> {
            Replace<T>(new DelegateProcessor<TPIn, TPOut>(conversion));
        }
        public void Remove<T, TPIn>() where T : Processor<TPIn, TPIn> => Replace<T, TPIn, TPIn>(input => input);
        public void AddBefore<T, TPIn, TPOut>(Processor<TPIn, TPIn> beforeProcessor) where T : Processor<TPIn, TPOut> {
            foreach (var stage in this) {
                var processorStage = stage as PipelineStage<TPOut, TPIn>;
                if (processorStage != null) {
                    if (processorStage.Processor is T)
                        processorStage.Processor = new MultiProcessor<TPIn, TPIn, TPOut>(beforeProcessor, processorStage.Processor);
                }
            }
        }
        public void AddAfter<T, TPIn, TPOut>(Processor<TPOut, TPOut> afterProcessor) where T : Processor<TPIn, TPOut> {
            foreach (var stage in this) {
                var processorStage = stage as PipelineStage<TPOut, TPIn>;
                if (processorStage != null) {
                    if (processorStage.Processor is T)
                        processorStage.Processor = new MultiProcessor<TPIn, TPOut, TPOut>(processorStage.Processor, afterProcessor);
                }
            }
        }
        public T? FindProcessor<T>() where T : Processor {
            foreach (var stage in this) {
                var processorStage = stage as IHasProcessor;
                if (processorStage != null) {
                    if (processorStage.Processor is T)
                        return (T)processorStage.Processor;
                }
            }
            return null;
        }


        private List<PipelineStage> Stages { get; }

        public IEnumerator<PipelineStage> GetEnumerator() {
            return this.Stages.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator() {
            return this.Stages.GetEnumerator();
        }
    }
}
