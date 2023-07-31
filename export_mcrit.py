import json

from mcrit.client.McritClient import McritClient


c = McritClient()
sample_id_to_entry = c.getSamples()
for sample_id, sample_entry in sample_id_to_entry.items():
    exported_json = c.getExportData([sample_id])
    bitness = "_x64" if sample_entry.bitness == 64 else "_x86"
    with open(sample_entry.filename[:-3]+ bitness + ".mcrit", "w") as fout:
        json.dump(exported_json, fout, indent=1)
