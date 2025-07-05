const express = require('express');
const router = express.Router();

// Get all security recommendations
router.get('/', async (req, res) => {
  try {
    const db = require('../services/databaseService');
    
    const query = `
      SELECT 
        id,
        title,
        category,
        priority,
        status,
        source,
        description,
        created_at,
        updated_at
      FROM security_recommendations 
      ORDER BY 
        CASE priority 
          WHEN 'critical' THEN 1
          WHEN 'high' THEN 2  
          WHEN 'medium' THEN 3
          WHEN 'low' THEN 4
        END,
        created_at DESC
    `;
    
    const { rows } = await db.pool.query(query);
    
    res.json({
      success: true,
      data: rows
    });
    
  } catch (error) {
    console.error('Error fetching recommendations:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch recommendations'
    });
  }
});

// Update recommendation status
router.patch('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    
    const db = require('../services/databaseService');
    
    const query = `
      UPDATE security_recommendations 
      SET status = $1, updated_at = NOW()
      WHERE id = $2
      RETURNING *
    `;
    
    const { rows } = await db.pool.query(query, [status, id]);
    
    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Recommendation not found'
      });
    }
    
    res.json({
      success: true,
      data: rows[0]
    });
    
  } catch (error) {
    console.error('Error updating recommendation:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update recommendation'
    });
  }
});

module.exports = router; 