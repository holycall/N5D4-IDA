"""Private N5D4 training worker. The IDA process only sends numeric features."""

import json
import math
import sys
from pathlib import Path

import torch
from ltn import fuzzy_ops
from torch import nn


def train(dataset, epochs, checkpoint):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    torch.manual_seed(42)
    if device.type == "cpu":
        torch.set_num_threads(min(torch.get_num_threads(), 4))
    features = torch.tensor(dataset["features"], dtype=torch.float32, device=device)
    model = nn.Sequential(nn.Linear(9, 32), nn.ReLU(), nn.Linear(32, 64),
                          nn.ReLU(), nn.Linear(64, 1), nn.Sigmoid()).to(device)
    if checkpoint.exists():
        model.load_state_dict(torch.load(checkpoint, map_location=device, weights_only=True))
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    forall = fuzzy_ops.AggregPMeanError(p=4)
    implies = fuzzy_ops.ImpliesReichenbach()
    equivalent = fuzzy_ops.Equiv(fuzzy_ops.AndProd(), implies)

    # Ground each quantified rule only over its matching blocks / observed pairs.
    # Indexing the two edge columns in parallel implements diagonal quantification.
    unary = [(torch.tensor(indices, device=device), positive)
             for positive, indices in dataset["unary"] if indices]
    relations = [(torch.tensor(pairs, device=device).T, connective)
                 for pairs, connective in ((dataset["fallthrough"], implies),
                                           (dataset["transfer"], equivalent)) if pairs]
    if not unary and not relations:
        return {"scores": [], "reason": "No grounded rules for this database."}

    for epoch in range(1, epochs + 1):
        scores = model(features).flatten()
        rules = [forall(scores[idx] if positive else 1 - scores[idx])
                 for idx, positive in unary]
        for (source, target), connective in relations:
            rules.append(forall(connective(scores[source], scores[target])))
        loss = 1 - forall(torch.stack(rules))
        value = loss.item()
        if not math.isfinite(value):
            raise ValueError("Non-finite rule satisfaction during training")
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        if value < 0.01:
            break
    with torch.no_grad():
        scores = model(features).flatten().cpu().tolist()
    torch.save(model.state_dict(), checkpoint)
    return {"scores": scores, "epochs": epoch, "loss": value, "device": str(device)}


def main(folder, epochs):
    folder = Path(folder)
    with (folder / "features.json").open(encoding="utf-8") as stream:
        dataset = json.load(stream)
    result = train(dataset, epochs, folder / "model.pt")
    with (folder / "result.json").open("w", encoding="utf-8") as stream:
        json.dump(result, stream, allow_nan=False)


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]))
