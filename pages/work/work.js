// pages/work.js
Page({

  /**
   * 页面的初始数据
   */
  data: {

  },

  /**
   * 生命周期函数--监听页面加载
   */
  onLoad: function (options) {

  },

  clickBtn1: function (e) {
    wx.navigateTo({
      url: '/pages/apply/apply'
    })
  },

  clickBtn2: function (e) {
    wx.navigateTo({
      url: '/pages/check/check'
    })
  },

  clickBtn3: function (e) {
    wx.navigateTo({
      url: '/pages/appeal/appeal'
    })
  }
  
})