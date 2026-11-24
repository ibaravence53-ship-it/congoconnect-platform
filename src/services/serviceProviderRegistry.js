const providers = [
  {
    id: 'momo-cg',
    name: 'MTN MoMo Congo',
    category: 'paiement',
    city: 'Pointe-Noire',
    active: true
  },
  {
    id: 'airtel-money-cg',
    name: 'Airtel Money Congo',
    category: 'paiement',
    city: 'Pointe-Noire',
    active: true
  },
  {
    id: 'etat-civil-sim',
    name: 'Guichet Identite Simule',
    category: 'identite',
    city: 'Brazzaville',
    active: true
  }
];

function listProviders(category) {
  const filter = typeof category === 'string' ? category.trim().toLowerCase() : '';
  if (!filter) {
    return providers;
  }
  return providers.filter((item) => item.category.toLowerCase() === filter);
}

module.exports = {
  listProviders
};
