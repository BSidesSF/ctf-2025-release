import random

# Configuration for dragon characteristics
dragon_data = {
    'colors': ['Quantum Violet', 'Nebula Chrome', 'Psychedelic Obsidian', 
               'Bioluminescent Amber', 'Singularity White', 'Dark Matter Gray',
               'Stellar Maroon', 'Blackhole Iris', 'Supernova Checkered',
               'Timeworn Patina', 'Celestial Plaid', 'Polymetallic Shimmer'],
    'sizes': ['Tiny', 'Small', 'Medium', 'Large', 'Colossal', 'Planetary'],
    'habitats': ['Neutron Star Fields', 'Precursor Ruins', 'Quantum Foam',
                'Dyson Sphere Remnants', 'Bioship Hives', 'Dark Matter Forests',
                'Temporal Rifts', 'Nano-Swarm Clouds', 'Photon Jungles',
                'Gravity Well Oases']
}

# Generate 100 unique dragons
dragons = []
for i in range(1, 101):
    dragons.append((
        f"Dragon-{i:03d}",
        random.choice(dragon_data['colors']),
        random.choice(dragon_data['sizes']),
        random.choice(dragon_data['habitats']),
        random.choices([0, 1], weights=[0.95, 0.05])[0]
    ))

# Generate SQL import file
sql = """BEGIN TRANSACTION;
INSERT INTO dragons (name, color, size, habitat, is_classified) VALUES\n"""
sql += ",\n".join([f"  ('{name}', '{color}', '{size}', '{habitat}', {classified})" 
                  for name, color, size, habitat, classified in dragons])
sql += ";\nCOMMIT;"

print(sql)
