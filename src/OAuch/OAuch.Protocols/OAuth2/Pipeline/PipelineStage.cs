using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.Pipeline {
    public abstract class PipelineStage {
        internal abstract StageList AllStages { get; }

        public bool HasProcessor<T>() where T : Processor => AllStages.HasProcessor<T>();
        public void Replace<T, TPIn, TPOut>(Processor newProcessor) where T : Processor => AllStages.Replace<T>(newProcessor);
        public void Replace<T, TPIn, TPOut>(Func<TPIn, TPOut> conversion) where T : Processor<TPIn, TPOut> => AllStages.Replace<T, TPIn, TPOut>(conversion);
        public void Remove<T, TPIn>() where T : Processor<TPIn, TPIn> => AllStages.Remove<T, TPIn>();
        public void AddBefore<T, TPIn, TPOut>(Processor<TPIn, TPIn> beforeProcessor) where T : Processor<TPIn, TPOut> => AllStages.AddBefore<T, TPIn, TPOut>(beforeProcessor);
        public void AddAfter<T, TPIn, TPOut>(Processor<TPOut, TPOut> afterProcessor) where T : Processor<TPIn, TPOut> => AllStages.AddAfter<T, TPIn, TPOut>(afterProcessor);
        public T? FindProcessor<T>() where T : Processor => AllStages.FindProcessor<T>();
    }
    public abstract class PipelineStage<T> : PipelineStage {
        public abstract Task<bool> Run(IProvider tokenProvider, TokenResult tokenResult);
        public virtual T? Result { get; protected set; }
    }
    public class PipelineStage<T, TPrev> : PipelineStage<T>, IHasProcessor {
        public PipelineStage(PipelineStage<TPrev> previous, Processor<TPrev, T> processor) {
            _previous = previous;
            this.Processor = processor;
            this.AllStages = previous.AllStages;
            this.AllStages.AddStage(this);
        }
        private PipelineStage<TPrev> _previous;
        
        public Processor<TPrev, T> Processor { get; set; }
        Processor IHasProcessor.Processor {
            get {
                return this.Processor;
            }
            set {
                this.Processor = (Processor<TPrev, T>)value;
            }
        }

        internal override StageList AllStages { get; }


        public async override Task<bool> Run(IProvider tokenProvider, TokenResult tokenResult) {
            var succeeded = await _previous.Run(tokenProvider, tokenResult);
            if (succeeded) {
                this.Result = await Processor.Process(_previous.Result!, tokenProvider, tokenResult);
                return Processor.Succeeded;
            } else {
                return false;
            }
        }
    }
}
