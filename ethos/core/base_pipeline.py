"""
ethos.core.base_pipeline
========================
Chains BaseModule instances in sequence to form a processing pipeline.
"""

from __future__ import annotations

from typing import List

from ethos.core.base_module import BaseModule
from ethos.core.data_types import DataRecord, ProcessedRecord


class BasePipeline:
    """
    Chains multiple BaseModule instances in sequence.

    Each module's ProcessedRecord output is converted back to a
    DataRecord and passed to the next module in the chain.

    Usage
    -----
    pipeline = BasePipeline([privacy_layer, fairness_layer, model_layer])
    result = pipeline.run(DataRecord(content=user_input))
    """

    def __init__(self, modules: List[BaseModule]):
        """
        Parameters
        ----------
        modules : list of BaseModule
            Ordered list of modules to run in sequence.
        """
        if not modules:
            raise ValueError("BasePipeline requires at least one module.")
        self._modules = modules

    def run(self, record: DataRecord) -> ProcessedRecord:
        """
        Pass the DataRecord through each module in sequence.

        Parameters
        ----------
        record : DataRecord
            The initial input record.

        Returns
        -------
        ProcessedRecord
            Result from the final module in the chain.
        """
        current_record = record
        last_result: ProcessedRecord = None

        for module in self._modules:
            if not module._initialized:
                module.initialize()

            last_result = module.run(current_record)

            # Propagate the safe content forward as new input
            current_record = DataRecord(
                content=last_result.safe_content,
                session_id=current_record.session_id,
                metadata={**current_record.metadata, **last_result.metadata},
            )

        return last_result

    def add_module(self, module: BaseModule) -> "BasePipeline":
        """Append a module to the end of the pipeline. Returns self."""
        self._modules.append(module)
        return self

    def __repr__(self) -> str:
        names = " → ".join(m.layer_name for m in self._modules)
        return f"BasePipeline([{names}])"
