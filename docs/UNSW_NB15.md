# UNSW-NB15 adapter

NetGuard uses the official preconfigured training and testing files without
reshuffling them. This makes experiment runs comparable and prevents accidental
test leakage caused by creating a new random split across the combined dataset.

## Dataset

UNSW-NB15 contains normal traffic and nine attack families: Fuzzers, Analysis,
Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, and Worms. The
official split contains 175,341 training records and 82,332 testing records.

Official page: <https://research.unsw.edu.au/projects/unsw-nb15-dataset>

## Leakage controls

- `id` is excluded because it is a row identifier, not a network measurement.
- `label` and `attack_cat` are used only to build targets and never as features.
- preprocessing is fitted only on the training set.
- the fitted preprocessing pipeline and classifier are saved together.
- missing numeric and categorical values are imputed inside the pipeline.

## Tasks

The binary task maps `label=0` to `normal` and `label=1` to `attack`. The
multiclass task uses `Normal` plus the nine attack categories.

The first baseline is a class-balanced linear classifier with logistic loss,
optimized with stochastic gradient descent. It provides a fast and transparent
reference point before tree ensembles and calibrated models are compared.

## Required citation

Moustafa, N., & Slay, J. (2015). *UNSW-NB15: A comprehensive data set for
network intrusion detection systems*. MilCIS. DOI: 10.1109/MilCIS.2015.7348942.
